# Developed in Jan 2026, author carlos.netto@gmail.com.
# Purpose: Validate the X9.150 specification.
# Not for production use; intended only to prove the spec.

import time
import base64
import json
import uuid
import os
import hashlib
import argparse
import requests
import random
from flask import Flask, jsonify, request
from jose import jws
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import yaml
from jsonschema import Draft7Validator
import referencing
from referencing.jsonschema import DRAFT7

# --- CONFIGURATION ---
PORT = 5005
HOST = "localhost"
PAYLOAD_FILE = "payload.json"

app = Flask(__name__)

# In-memory state (loaded from file)
private_key_pem = None
payee_cert_b64 = None
payer_public_key = None
payee_thumbprint = None
jwk_metadata = {}
FAIL_SIGNATURE = False
FAIL_CORRELATION_ID = False
FAIL_JWS_CUSTOM = False
FAIL_IAT = False
FAIL_TTL = False
SANCTIONED_WALLET = None

def validate_against_spec(data, schema_name):
    """Validates JSON against the OpenAPI spec. Required for spec validation testing."""
    spec_path = os.path.join(os.path.dirname(__file__), "spec", "openapi.yaml")
    if not os.path.exists(spec_path):
        return
    with open(spec_path, 'r') as f:
        spec = yaml.safe_load(f)

    # Define a base URI for the spec to allow proper $ref resolution across the registry
    spec_uri = "http://x9.150/openapi.yaml"
    target_schema = {"$ref": f"{spec_uri}#/components/schemas/{schema_name}"}

    # Create a registry from the full spec to resolve internal $refs
    resource = referencing.Resource.from_contents(spec, default_specification=DRAFT7)
    registry = referencing.Registry().with_resource(uri=spec_uri, resource=resource)

    try:
        Draft7Validator(target_schema, registry=registry).validate(data)
        print(f"[OK] JSON validated against {schema_name}")
    except Exception as e:
        print(f"[!] Spec Validation Error ({schema_name}): {e}")

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
                # URLs shall adhere to the syntax dictated by RFC 3986.
                print(f"[*] Fetch URL:  http://{HOST}:{PORT}/fetch/{txn_id}")
                print(f"[*] Notify URL: http://{HOST}:{PORT}/notify/{txn_id}")

    print(f"[*] Payee keys and JWKS metadata loaded.")
    return True

def sign_jws(payload, key_pem, correlation_id=None, is_fetch=False):
    """Wraps the payload in a JWS structure (used for responses)."""
    iat = int(time.time())
    if FAIL_IAT:
        print("[!] Testing Mode: Intentionally returning an iat from 11 minutes ago.")
        iat -= 660 # 11 minutes ago

    ttl_val = (iat * 1000) + 60000 # 1 minute after iat
    if FAIL_TTL:
        print("[!] Testing Mode: Intentionally returning an expired ttl.")
        ttl_val = (int(time.time()) * 1000) - 1000 # 1 second ago
    
    effective_correlation_id = correlation_id or str(uuid.uuid4())

    if is_fetch and FAIL_CORRELATION_ID:
        print("[!] Testing Mode: Intentionally returning a wrong correlationId.")
        effective_correlation_id = str(uuid.uuid4())

    headers = {
        "alg": "ES256",
        "typ": "payresp+jws",
        "x5c": [payee_cert_b64],  # Embeds the cert directly to avoid HTTP hits
        "x5u": jwk_metadata.get("x5u"), # Kept as a standard fallback
        "x5t#S256": payee_thumbprint,
        "kid": jwk_metadata.get("kid"),
        "iat": iat,
        "ttl": ttl_val,
        "correlationId": effective_correlation_id,
        "crit": ["correlationId", "iat", "ttl"]
    }

    if FAIL_JWS_CUSTOM:
        fields = ["iat", "ttl", "correlationId"]
        to_remove = []
        while not to_remove:
            to_remove = [f for f in fields if random.choice([True, False])]
        
        print(f"[!] Testing Mode: Intentionally omitting JWS headers in response: {to_remove}")
        for field in to_remove:
            if field in headers:
                del headers[field]

    token = jws.sign(payload, key_pem, headers=headers, algorithm='ES256')

    if FAIL_SIGNATURE:
        print("[!] Testing Mode: Intentionally corrupting the signature (modifying the signature string).")
        parts = token.split('.')
        # Modify the last character of the signature part to invalidate it
        sig = parts[2]
        corrupted_sig = sig[:-1] + ('0' if sig[-1] != '0' else '1')
        return f"{parts[0]}.{parts[1]}.{corrupted_sig}"

    return token

def verify_jws(token):
    """Verifies a JWS using x5c (embedded) or x5u (remote via certserv)."""
    header = jws.get_unverified_header(token)
    # 1. Try x5c (Embedded - High Performance)
    if 'x5c' in header:
        cert_der = base64.b64decode(header['x5c'][0])
        cert = x509.load_der_x509_certificate(cert_der)
        payload = jws.verify(token, cert.public_key(), algorithms=['ES256'])
        return payload, header
    # 2. Try x5u (URL - uses certserv.py)
    if 'x5u' in header:
        r = requests.get(header['x5u'])
        cert = x509.load_pem_x509_certificate(r.content)
        payload = jws.verify(token, cert.public_key(), algorithms=['ES256'])
        return payload, header
    raise ValueError("No certificate found in JWS headers")

def validate_jws_headers(header):
    """Validates iat, ttl, and crit list in JWS headers for security and spec compliance."""
    # 1. Check 'crit' enforcement (RFC 7515)
    crit = header.get("crit", [])
    if not isinstance(crit, list):
        crit = []
        
    for field in crit:
        if field not in header:
            return False, f"Critical header '{field}' is missing."

    # 2. Validate iat (Issued At)
    now = int(time.time())
    iat = header.get("iat")
    if iat:
        if iat > now + 60: # 1 minute clock skew allowance
            return False, "iat is in the future."
        if now - iat > 480: # 8 minutes threshold
            return False, f"iat is too old ({now - iat} seconds ago)."
    
    # 3. Validate ttl (Time To Live)
    ttl = header.get("ttl")
    if ttl:
        now_ms = int(time.time() * 1000)
        if now_ms > ttl:
            return False, f"JWS has expired (ttl: {ttl}, current: {now_ms})."
            
    return True, None

@app.route('/fetch/<payload_id>', methods=['POST'])
def fetch_payload(payload_id):
    """Endpoint for Payer App to retrieve the Payment Payload (Section 6.2)."""
    raw_data = request.get_data(as_text=True).strip()
    try:
        incoming_headers = jws.get_unverified_header(raw_data)
    except Exception:
        body = {"statusCode": 400, "error": "Invalid JWS format"}
        return sign_jws(body, private_key_pem, is_fetch=True), 400, {'Content-Type': 'application/jose'}

    # Validate JWS headers (including 'crit' enforcement)
    is_valid, error_msg = validate_jws_headers(incoming_headers)
    if not is_valid:
        print(f"[!] JWS Header Validation Error: {error_msg}")
        body = {"statusCode": 400, "error": error_msg}
        return sign_jws(body, private_key_pem, incoming_headers.get("correlationId"), is_fetch=True), 400, {'Content-Type': 'application/jose'}

    # Verify Signature
    try:
        payload_bytes, _ = verify_jws(raw_data)
        claims = payload_bytes.decode('utf-8')
    except Exception as e:
        print(f"[!] Signature Verification Failed for Fetch: {e}")
        body = {"statusCode": 400, "error": "Invalid Signature"}
        return sign_jws(body, private_key_pem, incoming_headers.get("correlationId"), is_fetch=True), 400, {'Content-Type': 'application/jose'}

    print(f"\n[*] Incoming Fetch Request for ID: {payload_id}")
    print(f"[*] JWS Headers: {json.dumps(incoming_headers, indent=2)}")
    try:
        print(f"[*] JWS Body: {json.dumps(json.loads(claims), indent=2)}")
    except:
        print(f"[*] JWS Body: {claims}")

    if not os.path.exists(PAYLOAD_FILE):
        body = {"statusCode": 404, "error": "Payload file not found"}
        validate_against_spec(body, "SignedStatusCodePayload")
        signed_err = sign_jws(body, private_key_pem, incoming_headers.get("correlationId"), is_fetch=True)
        return signed_err, 404, {'Content-Type': 'application/jose'}

    with open(PAYLOAD_FILE, "r") as f:
        payload_data = json.load(f)

    if payload_data.get("id") != payload_id:
        print(f"[!] ID mismatch: Requested {payload_id}, found {payload_data.get('id')}")
        body = {"statusCode": 404, "error": "Payload ID mismatch"}
        validate_against_spec(body, "SignedStatusCodePayload")
        signed_err = sign_jws(body, private_key_pem, incoming_headers.get("correlationId"), is_fetch=True)
        return signed_err, 404, {'Content-Type': 'application/jose'}

    validate_against_spec(payload_data, "PaymentRequest")
    signed_payload = sign_jws(payload_data, private_key_pem, incoming_headers.get("correlationId"), is_fetch=True)
    return signed_payload, 200, {'Content-Type': 'application/jose'}

@app.route('/notify/<payload_id>', methods=['POST'])
def receive_notification(payload_id):
    """Endpoint for Payer PSP to send Payment Notification (Section 6.3)."""
    raw_data = request.get_data(as_text=True).strip()
    try:
        incoming_headers = jws.get_unverified_header(raw_data)
    except Exception:
        body = {"statusCode": 400, "error": "Invalid JWS format"}
        return sign_jws(body, private_key_pem), 400, {'Content-Type': 'application/jose'}

    # Validate JWS headers (including 'crit' enforcement)
    is_valid, error_msg = validate_jws_headers(incoming_headers)
    if not is_valid:
        print(f"[!] JWS Header Validation Error: {error_msg}")
        body = {"statusCode": 400, "error": error_msg}
        return sign_jws(body, private_key_pem, incoming_headers.get("correlationId")), 400, {'Content-Type': 'application/jose'}

    print(f"\n[*] Incoming Notification Request for ID: {payload_id}")
    print(f"[*] JWS Headers: {json.dumps(incoming_headers, indent=2)}")
    try:
        claims = jws.get_unverified_claims(raw_data)
        try:
            print(f"[*] JWS Body: {json.dumps(json.loads(claims), indent=2)}")
        except:
            print(f"[*] JWS Body: {claims}")
    except:
        print(f"[*] Raw Body: {raw_data}")

    if not os.path.exists(PAYLOAD_FILE):
        body = {"statusCode": 404, "error": "No active transaction found"}
        validate_against_spec(body, "SignedStatusCodePayload")
        return sign_jws(body, private_key_pem, incoming_headers.get("correlationId")), 404, {'Content-Type': 'application/jose'}

    with open(PAYLOAD_FILE, "r") as f:
        payload_data = json.load(f)

    if payload_data.get("id") != payload_id:
        body = {"statusCode": 404, "error": "Transaction ID mismatch"}
        validate_against_spec(body, "SignedStatusCodePayload")
        return sign_jws(body, private_key_pem, incoming_headers.get("correlationId")), 404, {'Content-Type': 'application/jose'}

    try:
        # Verify Signature using headers (x5c or certserv via x5u)
        payload_bytes, _ = verify_jws(raw_data)
        data = json.loads(payload_bytes.decode('utf-8'))
        validate_against_spec(data, "NotificationPayload")

        if SANCTIONED_WALLET:
            payer_addr = data.get("payer", {}).get("fromAddress")
            if payer_addr and str(payer_addr).lower() == SANCTIONED_WALLET.lower():
                print(f"[!] Security Alert: Payment blocked from sanctioned wallet {payer_addr}")
                body = {"statusCode": 403, "error": "Sanctioned wallet"}
                return sign_jws(body, private_key_pem, incoming_headers.get("correlationId")), 403, {'Content-Type': 'application/jose'}

        resp_body = {"statusCode": 200}
        validate_against_spec(resp_body, "SignedStatusCodePayload")
        signed_resp = sign_jws(resp_body, private_key_pem, incoming_headers.get("correlationId"))
        return signed_resp, 200, {'Content-Type': 'application/jose'}

    except Exception as e:
        print(f"\n[!] Error processing JWS: {e}")
        body = {"statusCode": 400, "error": "Invalid Request or Signature"}
        return sign_jws(body, private_key_pem, incoming_headers.get("correlationId")), 400, {'Content-Type': 'application/jose'}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="X9.150 Payee PSP Simulator")
    parser.add_argument("--failSignature", action="store_true", help="Intentionally corrupt the JWS signature for testing.")
    parser.add_argument("--failCorrelationId", action="store_true", help="Intentionally return a wrong correlationId in the /fetch response.")
    parser.add_argument("--failjwscustom", action="store_true", help="Intentionally omit mandatory JWS headers (iat, ttl, correlationId) randomly in responses.")
    parser.add_argument("--failiat", action="store_true", help="Intentionally return an iat from 11 minutes ago.")
    parser.add_argument("--failttl", action="store_true", help="Intentionally return an expired ttl.")
    parser.add_argument("--sanctionedWallet", help="Blockchain address to sanction/block.")
    args = parser.parse_args()

    FAIL_SIGNATURE = args.failSignature
    FAIL_CORRELATION_ID = args.failCorrelationId
    FAIL_JWS_CUSTOM = args.failjwscustom
    FAIL_IAT = args.failiat
    FAIL_TTL = args.failttl
    SANCTIONED_WALLET = args.sanctionedWallet

    if load_data():
        print(f"[*] Starting Payee Server at http://{HOST}:{PORT}...")
        # Binding to 127.0.0.1 ensures compatibility with both localhost and 127.0.0.1 access
        app.run(host='127.0.0.1', port=PORT, debug=False, use_reloader=False)