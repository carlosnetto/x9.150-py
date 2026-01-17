import time
import base64
import json
import uuid
import os
import hashlib
import requests
from flask import Flask, jsonify, request
from jose import jws
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# --- CONFIGURATION ---
PORT = 5000
HOST = "127.0.0.1"
PAYLOAD_FILE = "payload.json"

app = Flask(__name__)

# In-memory state (loaded from file)
private_key_pem = None
payee_cert_b64 = None
payer_public_key = None
payee_thumbprint = None
jwk_metadata = {}

def load_data():
    """Loads the generated ECC keys, certificates, and JWKS metadata."""
    global private_key_pem, payee_cert_b64, payer_public_key, payee_thumbprint, jwk_metadata

    # 1. Load the Private Key
    try:
        with open("payee_key.txt", "rb") as f:
            private_key_pem = f.read()
    except FileNotFoundError:
        print("[!] Error: payee_key.txt not found. Run keygen.py first.")
        return False

    # 2. Load the Certificate for x5c (to avoid extra HTTP hits)
    try:
        with open("payee_cert.pem", "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)
            # x5c requires DER format, then standard Base64 encoding
            payee_cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode('utf-8')
            
            # Calculate SHA256 thumbprint (x5t#S256) directly from the certificate
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            payee_thumbprint = base64.urlsafe_b64encode(hashlib.sha256(cert_der).digest()).rstrip(b'=').decode('ascii')
    except Exception as e:
        print(f"[!] Error loading payee_cert.pem: {e}")
        return False

    # 3. Load Payer's Public Key to verify incoming notifications
    try:
        with open("payer_cert.pem", "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)
            payer_public_key = cert.public_key()
    except FileNotFoundError:
        print("[!] Warning: payer_cert.pem not found. Notification verification will fail.")
        # We don't return False here to allow the server to start for fetching

    # 4. Load the JWKS metadata for JWS headers
    try:
        with open("payee.jwks", "r") as f:
            jwks = json.load(f)
            jwk_metadata = jwks["keys"][0]
    except (FileNotFoundError, IndexError, KeyError):
        print("[!] Error: payee.jwks is missing or invalid.")
        return False

    if not os.path.exists(PAYLOAD_FILE):
        print(f"[*] Warning: {PAYLOAD_FILE} not found. Ensure qr_generator.py is run.")
    else:
        with open(PAYLOAD_FILE, "r") as f:
            payload_data = json.load(f)
            txn_id = payload_data.get("id")
            if txn_id:
                print(f"[*] Fetch URL:  http://{HOST}:{PORT}/fetch/{txn_id}")
                print(f"[*] Notify URL: http://{HOST}:{PORT}/notify/{txn_id}")

    print(f"[*] Payee keys and JWKS metadata loaded.")
    return True

def sign_jws(payload, key_pem, correlation_id=None):
    """Wraps the payload in a JWS structure (used for responses)."""
    now_ms = int(time.time() * 1000)
    headers = {
        "alg": "ES256",
        "typ": "payresp+jws",
        "x5c": [payee_cert_b64],  # Embeds the cert directly to avoid HTTP hits
        "x5u": jwk_metadata.get("x5u"), # Kept as a standard fallback
        "x5t#S256": payee_thumbprint,
        "kid": jwk_metadata.get("kid"),
        "iat": now_ms,
        "ttl": 60000,
        "correlationId": correlation_id or uuid.uuid4().hex,
        "crit": ["correlationId", "iat", "ttl"]
    }
    return jws.sign(payload, key_pem, headers=headers, algorithm='ES256')

def verify_jws(token):
    """Verifies a JWS using x5c (embedded) or x5u (remote via certserv)."""
    header = jws.get_unverified_header(token)
    # 1. Try x5c (Embedded - High Performance)
    if 'x5c' in header:
        cert_der = base64.b64decode(header['x5c'][0])
        cert = x509.load_der_x509_certificate(cert_der)
        return jws.verify(token, cert.public_key(), algorithms=['ES256'])
    # 2. Try x5u (URL - uses certserv.py)
    if 'x5u' in header:
        r = requests.get(header['x5u'])
        cert = x509.load_pem_x509_certificate(r.content)
        return jws.verify(token, cert.public_key(), algorithms=['ES256'])
    raise ValueError("No certificate found in JWS headers")

@app.route('/fetch/<payload_id>', methods=['POST'])
def fetch_payload(payload_id):
    """Endpoint for Payer App to retrieve the Payment Payload (Section 6.2)."""
    raw_data = request.get_data(as_text=True).strip()
    incoming_headers = {}
    try:
        incoming_headers = jws.get_unverified_header(raw_data)
    except:
        pass

    if not os.path.exists(PAYLOAD_FILE):
        body = {"statusCode": 404, "error": "Payload file not found"}
        signed_err = sign_jws(body, private_key_pem, incoming_headers.get("correlationId"))
        return signed_err, 404, {'Content-Type': 'application/jose'}

    with open(PAYLOAD_FILE, "r") as f:
        payload_data = json.load(f)

    if payload_data.get("id") != payload_id:
        print(f"[!] ID mismatch: Requested {payload_id}, found {payload_data.get('id')}")
        body = {"statusCode": 404, "error": "Payload ID mismatch"}
        signed_err = sign_jws(body, private_key_pem, incoming_headers.get("correlationId"))
        return signed_err, 404, {'Content-Type': 'application/jose'}

    print(f"\n[*] Payment Payload Request Received for ID: {payload_id}")
    
    # Include statusCode in the successful business payload
    payload_data["statusCode"] = 200
    signed_payload = sign_jws(payload_data, private_key_pem, incoming_headers.get("correlationId"))
    return signed_payload, 200, {'Content-Type': 'application/jose'}

@app.route('/notify/<payload_id>', methods=['POST'])
def receive_notification(payload_id):
    """Endpoint for Payer PSP to send Payment Notification (Section 6.3)."""
    # Pre-extract headers for error reporting if possible
    raw_data = request.get_data(as_text=True).strip()
    incoming_headers = {}
    try:
        incoming_headers = jws.get_unverified_header(raw_data)
    except:
        pass

    if not os.path.exists(PAYLOAD_FILE):
        body = {"statusCode": 404, "error": "No active transaction found"}
        return sign_jws(body, private_key_pem, incoming_headers.get("correlationId")), 404, {'Content-Type': 'application/jose'}

    with open(PAYLOAD_FILE, "r") as f:
        payload_data = json.load(f)

    if payload_data.get("id") != payload_id:
        body = {"statusCode": 404, "error": "Transaction ID mismatch"}
        return sign_jws(body, private_key_pem, incoming_headers.get("correlationId")), 404, {'Content-Type': 'application/jose'}

    if raw_data.count('.') == 2:
        try:
            # Verify Signature using headers (x5c or certserv via x5u)
            data = json.loads(verify_jws(raw_data).decode('utf-8'))

            print(f"\n[!] Payment Notification Received for ID: {payload_id}")
            print(json.dumps(data, indent=2))

            resp_body = {"statusCode": 200}
            signed_resp = sign_jws(resp_body, private_key_pem, incoming_headers.get("correlationId"))
            return signed_resp, 200, {'Content-Type': 'application/jose'}

        except Exception as e:
            print(f"\n[!] Error processing JWS: {e}")
            body = {"statusCode": 400, "error": "Invalid Request or Signature"}
            return sign_jws(body, private_key_pem, incoming_headers.get("correlationId")), 400, {'Content-Type': 'application/jose'}

    print(f"\n[!] Invalid Notification Format Received for ID: {payload_id}")
    body = {"statusCode": 400, "error": "Invalid request format. Expected JWS."}
    return sign_jws(body, private_key_pem), 400, {'Content-Type': 'application/jose'}

if __name__ == "__main__":
    if load_data():
        print(f"[*] Starting Payee Server at http://{HOST}:{PORT}...")
        app.run(host=HOST, port=PORT, debug=False, use_reloader=False)