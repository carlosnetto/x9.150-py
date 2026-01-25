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
PAYLOAD_DIR = "payee_db/qrs"
CACHE_DIR = "payee_db/cache"

app = Flask(__name__)

# In-memory state (loaded from file)
private_key_pem = None
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
        print(f"QR_SERVER: [OK] JSON validated against {schema_name}")
    except Exception as e:
        print(f"QR_SERVER: [!] Spec Validation Error ({schema_name}): {e}")

def load_data():
    """Loads the generated ECC keys, certificates, and JWKS metadata."""
    global private_key_pem, payee_thumbprint, jwk_metadata

    # 1. Load the Private Key
    try:
        with open("payee_db/certs/payee_key.txt", "rb") as f:
            private_key_pem = f.read()
    except FileNotFoundError:
        print("QR_SERVER: [!] Error: payee_key.txt not found. Run keygen.py first.")
        return False

    # 2. Load the JWKS metadata for JWS headers and thumbprint
    try:
        with open("payee_db/certs/payee.jwks", "r") as f:
            jwks = json.load(f)
            jwk_metadata = jwks["keys"][0]
            payee_thumbprint = jwk_metadata.get("x5t#S256")
    except (FileNotFoundError, IndexError, KeyError):
        print("QR_SERVER: [!] Error: payee.jwks is missing or invalid.")
        return False

    if not os.path.exists(PAYLOAD_DIR):
        os.makedirs(PAYLOAD_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)

    print(f"QR_SERVER: [*] Payee keys and JWKS metadata loaded.")
    return True

def sign_jws(payload, key_pem, correlation_id=None, is_fetch=False):
    """Wraps the payload in a JWS structure (used for responses)."""
    # JWS (JSON Web Signature) consists of three parts: Header.Payload.Signature
    # The Header contains metadata (who signed it, what algorithm).
    # The Payload is the actual data (the payment details).
    # The Signature is the cryptographic proof of authenticity.

    iat = int(time.time())
    if FAIL_IAT:
        print("QR_SERVER: [!] Testing Mode: Intentionally returning an iat from 11 minutes ago.")
        iat -= 660 # 11 minutes ago

    ttl_val = (iat * 1000) + 60000 # 1 minute after iat
    if FAIL_TTL:
        print("QR_SERVER: [!] Testing Mode: Intentionally returning an expired ttl.")
        ttl_val = (int(time.time()) * 1000) - 1000 # 1 second ago
    
    effective_correlation_id = correlation_id or str(uuid.uuid4())

    if is_fetch and FAIL_CORRELATION_ID:
        print("QR_SERVER: [!] Testing Mode: Intentionally returning a wrong correlationId.")
        effective_correlation_id = str(uuid.uuid4())

    headers = {
        "alg": "ES256", # ECDSA using P-256 and SHA-256
        "typ": "payresp+jws", # X9.150 specific type for payment responses
        "jku": jwk_metadata.get("jku"),
        "kid": jwk_metadata.get("kid"),
        "iat": iat, # Issued At: Prevents replay attacks
        "ttl": ttl_val, # Time To Live: Ensures the message is fresh
        # correlationId: Links the response to the original request for non-repudiation
        "correlationId": effective_correlation_id,
        "crit": ["correlationId", "iat", "ttl"],
        "x5t#S256": payee_thumbprint
    }

    if FAIL_JWS_CUSTOM:
        fields = ["iat", "ttl", "correlationId"]
        to_remove = []
        while not to_remove:
            to_remove = [f for f in fields if random.choice([True, False])]
        
        print(f"QR_SERVER: [!] Testing Mode: Intentionally omitting JWS headers in response: {to_remove}")
        for field in to_remove:
            if field in headers:
                del headers[field]

    token = jws.sign(payload, key_pem, headers=headers, algorithm='ES256')

    if FAIL_SIGNATURE:
        print("QR_SERVER: [!] Testing Mode: Intentionally corrupting the signature (modifying the signature string).")
        parts = token.split('.')
        # Modify the first character of the signature part to invalidate it
        sig = parts[2]
        corrupted_sig = ('0' if sig[0] != '0' else '1') + sig[1:]
        return f"{parts[0]}.{parts[1]}.{corrupted_sig}"

    return token

def verify_jws(token):
    """Verifies a JWS using cache or jku (remote)."""
    header = jws.get_unverified_header(token)
    thumbprint = header.get("x5t#S256")
    cert = None
    
    # 1. Try Cache
    if thumbprint:
        cache_path = os.path.join(CACHE_DIR, f"{thumbprint}.pem")
        if os.path.exists(cache_path):
            print(f"QR_SERVER: Cache Hit for certificate {thumbprint}")
            with open(cache_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())

    # 2. Try jku (JWK Set URL)
    if not cert and 'jku' in header:
        print(f"QR_SERVER: Fetching certificate from {header['jku']}")
        r = requests.get(header['jku'])
        if r.status_code == 200:
            try:
                # Try to parse as JWKS first
                jwks = r.json()
                for key in jwks.get("keys", []):
                    if key.get("kid") == header.get("kid") and "x5c" in key:
                        cert_der = base64.b64decode(key["x5c"][0])
                        cert = x509.load_der_x509_certificate(cert_der)
                        break
            except (json.JSONDecodeError, ValueError):
                # Fallback to raw PEM if it's not JSON
                cert = x509.load_pem_x509_certificate(r.content)
                
        else:
            print(f"QR_SERVER: [!] Failed to fetch certificate from jku: {r.status_code}")

    if not cert:
        raise ValueError("No certificate found in JWS headers or cache")

    # Verify Signature
    payload = jws.verify(token, cert.public_key(), algorithms=['ES256'])
    
    # Update Cache
    if thumbprint and cert:
        calculated_thumbprint = base64.urlsafe_b64encode(hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest()).rstrip(b'=').decode('ascii')
        if calculated_thumbprint == thumbprint:
            cache_path = os.path.join(CACHE_DIR, f"{thumbprint}.pem")
            if not os.path.exists(cache_path):
                with open(cache_path, "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
                print(f"QR_SERVER: Cached certificate {thumbprint}")

    return payload, header

def validate_jws_headers(header):
    """Validates iat, ttl, and crit list in JWS headers for security and spec compliance."""
    # 1. Check 'crit' enforcement (RFC 7515)
    # The 'crit' header lists fields that the receiver MUST understand and validate.
    # If a receiver sees a field in 'crit' that it doesn't support, it must reject the JWS.
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
    # This is the first step after scanning. The Payer app asks: 
    # "I scanned this QR, what are the payment details?"
    raw_data = request.get_data(as_text=True).strip()
    try:
        incoming_headers = jws.get_unverified_header(raw_data)
    except Exception:
        body = {"statusCode": 400, "error": "Invalid JWS format"}
        return sign_jws(body, private_key_pem, is_fetch=True), 400, {'Content-Type': 'application/jose'}

    # Validate JWS headers (including 'crit' enforcement)
    is_valid, error_msg = validate_jws_headers(incoming_headers)
    if not is_valid:
        print(f"QR_SERVER: [!] JWS Header Validation Error: {error_msg}")
        body = {"statusCode": 400, "error": error_msg}
        return sign_jws(body, private_key_pem, incoming_headers.get("correlationId"), is_fetch=True), 400, {'Content-Type': 'application/jose'}

    # Verify Signature
    try:
        payload_bytes, _ = verify_jws(raw_data)
        claims = payload_bytes.decode('utf-8')
    except Exception as e:
        print(f"QR_SERVER: [!] Signature Verification Failed for Fetch: {e}")
        body = {"statusCode": 400, "error": "Invalid Signature"}
        return sign_jws(body, private_key_pem, incoming_headers.get("correlationId"), is_fetch=True), 400, {'Content-Type': 'application/jose'}

    print(f"\nQR_SERVER: [*] Incoming Fetch Request for ID: {payload_id}")
    print(f"QR_SERVER: [*] JWS Headers: {json.dumps(incoming_headers, indent=2)}")
    try:
        print(f"QR_SERVER: [*] JWS Body: {json.dumps(json.loads(claims), indent=2)}")
    except:
        print(f"QR_SERVER: [*] JWS Body: {claims}")

    payload_path = os.path.join(PAYLOAD_DIR, f"{payload_id}.json")
    if not os.path.exists(payload_path):
        body = {"statusCode": 404, "error": "Payload not found"}
        validate_against_spec(body, "SignedStatusCodePayload")
        signed_err = sign_jws(body, private_key_pem, incoming_headers.get("correlationId"), is_fetch=True)
        return signed_err, 404, {'Content-Type': 'application/jose'}

    with open(payload_path, "r") as f:
        payload_data = json.load(f)

    if payload_data.get("id") != payload_id:
        print(f"QR_SERVER: [!] ID mismatch: Requested {payload_id}, found {payload_data.get('id')}")
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
    # This is the final step. The Payer app says: 
    # "I have sent the money, here is the transaction hash/proof."
    raw_data = request.get_data(as_text=True).strip()
    try:
        incoming_headers = jws.get_unverified_header(raw_data)
    except Exception:
        body = {"statusCode": 400, "error": "Invalid JWS format"}
        return sign_jws(body, private_key_pem), 400, {'Content-Type': 'application/jose'}

    # Validate JWS headers (including 'crit' enforcement)
    is_valid, error_msg = validate_jws_headers(incoming_headers)
    if not is_valid:
        print(f"QR_SERVER: [!] JWS Header Validation Error: {error_msg}")
        body = {"statusCode": 400, "error": error_msg}
        return sign_jws(body, private_key_pem, incoming_headers.get("correlationId")), 400, {'Content-Type': 'application/jose'}

    print(f"\nQR_SERVER: [*] Incoming Notification Request for ID: {payload_id}")
    print(f"QR_SERVER: [*] JWS Headers: {json.dumps(incoming_headers, indent=2)}")
    try:
        claims = jws.get_unverified_claims(raw_data)
        try:
            print(f"QR_SERVER: [*] JWS Body: {json.dumps(json.loads(claims), indent=2)}")
        except:
            print(f"QR_SERVER: [*] JWS Body: {claims}")
    except:
        print(f"QR_SERVER: [*] Raw Body: {raw_data}")

    payload_path = os.path.join(PAYLOAD_DIR, f"{payload_id}.json")
    if not os.path.exists(payload_path):
        body = {"statusCode": 404, "error": "No active transaction found"}
        validate_against_spec(body, "SignedStatusCodePayload")
        return sign_jws(body, private_key_pem, incoming_headers.get("correlationId")), 404, {'Content-Type': 'application/jose'}

    with open(payload_path, "r") as f:
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
                print(f"QR_SERVER: [!] Security Alert: Payment blocked from sanctioned wallet {payer_addr}")
                body = {"statusCode": 403, "error": "Sanctioned wallet"}
                return sign_jws(body, private_key_pem, incoming_headers.get("correlationId")), 403, {'Content-Type': 'application/jose'}

        resp_body = {"statusCode": 200}
        validate_against_spec(resp_body, "SignedStatusCodePayload")
        signed_resp = sign_jws(resp_body, private_key_pem, incoming_headers.get("correlationId"))
        return signed_resp, 200, {'Content-Type': 'application/jose'}

    except Exception as e:
        print(f"\nQR_SERVER: [!] Error processing JWS: {e}")
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
        print(f"QR_SERVER: [*] Starting Payee Server at http://{HOST}:{PORT}...")
        # Binding to 127.0.0.1 ensures compatibility with both localhost and 127.0.0.1 access
        app.run(host='127.0.0.1', port=PORT, debug=False, use_reloader=False)