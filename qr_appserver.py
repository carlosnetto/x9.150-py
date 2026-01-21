# Developed in Jan 2026, author carlos.netto@gmail.com.
# Purpose: Validate the X9.150 specification.
# Not for production use; intended only to prove the spec.

import os
import sys
import json
import subprocess
import tempfile
import re
import base64
import uuid
import time
import hashlib
import requests
import yaml
import argparse
from flask import Flask, request, jsonify
from flask_cors import CORS
from jose import jws
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from jsonschema import Draft7Validator
import referencing
from referencing.jsonschema import DRAFT7

app = Flask(__name__)
CORS(app)
PORT = 5010
CACHE_DIR = "payer_db/cache"
USE_X5C = False
QR_SERVER_BASE_URL = "http://127.0.0.1:5005"

# --- Helper Functions (Copied/Adapted from qr_payer.py) ---

def parse_emv_tlv(data):
    """Helper to parse EMV TLV format."""
    results = {}
    i = 0
    while i < len(data):
        tag = data[i:i+2]
        length = int(data[i+2:i+4])
        value = data[i+4:i+4+length]
        results[tag] = value
        i += 4 + length
    return results

def extract_fetch_url(emv_str):
    """Extracts the URL from Tag 26, Subtag 01."""
    tags = parse_emv_tlv(emv_str)
    if "26" not in tags:
        raise ValueError("Tag 26 not found in QR content.")
    subtags = parse_emv_tlv(tags["26"])
    if "01" not in subtags:
        raise ValueError("Subtag 01 not found within Tag 26.")
    url = subtags["01"]
    if not url.startswith("http"):
        url = "http://" + url
    return url

def load_payer_identity():
    """Loads the persistent Payer keys. Required to sign requests sent to the upstream qr_server."""
    try:
        with open("payer_db/certs/payer_key.txt", "rb") as f:
            private_pem = f.read()
        with open("payer_db/certs/payer_cert.pem", "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            cert_b64 = base64.b64encode(cert_der).decode('utf-8')
            thumbprint = base64.urlsafe_b64encode(hashlib.sha256(cert_der).digest()).rstrip(b'=').decode('ascii')
        with open("payer_db/certs/payer.jwks", "r") as f:
            jwks = json.load(f)
            x5u = jwks["keys"][0].get("x5u")
        return private_pem, cert_b64, x5u, thumbprint
    except FileNotFoundError:
        print("QR_APPSERVER: [!] Error: Payer keys/certs not found.")
        return None, None, None, None

def verify_jws(token):
    """Verifies a JWS using cache, x5c, or x5u. Required to validate the signed response from the upstream qr_server."""
    header = jws.get_unverified_header(token)
    thumbprint = header.get("x5t#S256")
    cert = None
    
    if thumbprint:
        cache_path = os.path.join(CACHE_DIR, f"{thumbprint}.pem")
        if os.path.exists(cache_path):
            print(f"QR_APPSERVER: Cache Hit for certificate {thumbprint}")
            with open(cache_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())

    if not cert and 'x5c' in header:
        cert_der = base64.b64decode(header['x5c'][0])
        cert = x509.load_der_x509_certificate(cert_der)
        
    if not cert and 'x5u' in header:
        print(f"QR_APPSERVER: Fetching certificate from {header['x5u']}")
        r = requests.get(header['x5u'])
        cert = x509.load_pem_x509_certificate(r.content)

    if not cert:
        raise ValueError("No certificate found in JWS headers or cache")

    payload = jws.verify(token, cert.public_key(), algorithms=['ES256'])
    
    if thumbprint and cert:
        calculated = base64.urlsafe_b64encode(hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest()).rstrip(b'=').decode('ascii')
        if calculated == thumbprint:
            cache_path = os.path.join(CACHE_DIR, f"{thumbprint}.pem")
            if not os.path.exists(cache_path):
                with open(cache_path, "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
                print(f"QR_APPSERVER: Cached certificate {thumbprint}")

    return payload, header

def validate_jws_headers(header, expected_correlation_id=None):
    crit = header.get("crit", [])
    if not isinstance(crit, list): crit = []
    for field in crit:
        if field not in header:
            print(f"QR_APPSERVER: [!] Missing critical header '{field}'")
            return False
    if expected_correlation_id:
        if header.get("correlationId") != expected_correlation_id:
            print(f"QR_APPSERVER: [!] correlationId mismatch")
            return False
    now = int(time.time())
    iat = header.get("iat")
    if iat and (iat > now + 60 or now - iat > 480):
        print("QR_APPSERVER: [!] Invalid iat")
        return False
    ttl = header.get("ttl")
    if ttl and (int(time.time() * 1000) > ttl):
        print("QR_APPSERVER: [!] Expired ttl")
        return False
    return True

def validate_against_spec(data, schema_name):
    spec_path = os.path.join(os.path.dirname(__file__), "spec", "openapi.yaml")
    if not os.path.exists(spec_path): return
    with open(spec_path, 'r') as f: spec = yaml.safe_load(f)
    spec_uri = "http://x9.150/openapi.yaml"
    target_schema = {"$ref": f"{spec_uri}#/components/schemas/{schema_name}"}
    resource = referencing.Resource.from_contents(spec, default_specification=DRAFT7)
    registry = referencing.Registry().with_resource(uri=spec_uri, resource=resource)
    try:
        Draft7Validator(target_schema, registry=registry).validate(data)
        print(f"QR_APPSERVER: [OK] JSON validated against {schema_name}")
    except Exception as e:
        print(f"QR_APPSERVER: [!] Spec Validation Error ({schema_name}): {e}")

@app.route('/generate', methods=['POST'])
def generate_qr():
    """
    Receives a Payment Request JSON (template), calls qr_generator.py,
    and returns the generated QR content string.
    """
    data = request.get_json()
    if not data:
        print("QR_APPSERVER: [!] Received invalid JSON payload")
        return jsonify({"error": "Invalid JSON"}), 400

    print("QR_APPSERVER: [*] Received QR generation request")

    # Create a temporary file for the template
    # We close it immediately so qr_generator.py can open it
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp:
        json.dump(data, tmp)
        tmp_path = tmp.name

    try:
        # Call qr_generator.py
        # We assume qr_generator.py is in the current working directory
        cmd = [sys.executable, "qr_generator.py", tmp_path]
        
        # If a domain is needed in the future, it could be passed here
        # cmd.append(domain) 

        print(f"QR_APPSERVER: [DEBUG] Executing: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"QR_APPSERVER: [!] qr_generator failed: {result.stderr}")
            return jsonify({"error": "qr_generator failed", "details": result.stderr}), 500

        # Parse stdout to find the txt file path
        # Expected output line from qr_generator.py: 
        # [*] Raw QR string saved to 'payer_db/qrs/...'
        match = re.search(r"\[\*\] Raw QR string saved to '([^']+)'", result.stdout)
        if not match:
            print("QR_APPSERVER: [!] Could not parse output filename from qr_generator stdout")
            print(f"QR_APPSERVER: [DEBUG] Stdout: {result.stdout}")
            return jsonify({"error": "Could not determine output file"}), 500
        
        txt_path = match.group(1)
        print(f"QR_APPSERVER: [*] Generated file at: {txt_path}")
        
        if not os.path.exists(txt_path):
             print(f"QR_APPSERVER: [!] File not found: {txt_path}")
             return jsonify({"error": "Generated file not found"}), 500

        with open(txt_path, 'r') as f:
            qr_content = f.read()

        return jsonify({
            "qrContent": qr_content,
            "filePath": txt_path
        })

    except Exception as e:
        print(f"QR_APPSERVER: [!] Exception: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        # Clean up the temporary template file
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

@app.route('/fetch', methods=['POST'])
def fetch_payment_details():
    """
    Receives qrCodeContent, extracts URL, calls upstream qr_server, 
    verifies response, and returns the Payment Request JSON.

    NOTE: This endpoint acts as a gateway. It receives plain JSON from the client,
    but MUST use JWS (JSON Web Signature) to communicate with the upstream X9.150 
    compliant qr_server. The JWS management code is required to authenticate 
    as a valid Payer and to verify the integrity/authenticity of the Payee's response.
    """
    data = request.get_json()
    if not data or "qrCodeContent" not in data:
        return jsonify({"error": "Missing qrCodeContent"}), 400
    
    qr_content = data["qrCodeContent"]
    print(f"QR_APPSERVER: [*] Received Fetch Request for QR content")

    try:
        fetch_url = extract_fetch_url(qr_content)
        print(f"QR_APPSERVER: [*] Extracted URL: {fetch_url}")
    except Exception as e:
        return jsonify({"error": f"Invalid QR Content: {str(e)}"}), 400

    # Prepare JWS
    correlation_id = str(uuid.uuid4())
    qr_b64url = base64.urlsafe_b64encode(qr_content.encode()).decode().rstrip("=")
    payload = {"qrCodeContent": qr_b64url}
    
    validate_against_spec(payload, "FetchRequestPayload")

    private_key_pem, cert_b64, payer_x5u, payer_thumbprint = load_payer_identity()
    if not private_key_pem:
        return jsonify({"error": "Server identity not configured"}), 500

    iat = int(time.time())
    ttl = (iat * 1000) + 60000
    headers = {
        "alg": "ES256",
        "typ": "payreq+jws",
        "x5u": payer_x5u,
        "kid": "payer-key-id-001",
        "iat": iat,
        "ttl": ttl,
        "correlationId": correlation_id,
        "crit": ["iat", "ttl", "correlationId"]
    }
    
    if USE_X5C:
        headers["x5c"] = [cert_b64]
    else:
        headers["x5t#S256"] = payer_thumbprint

    token = jws.sign(payload, private_key_pem, headers=headers, algorithm='ES256')

    try:
        resp = requests.post(fetch_url, data=token, headers={'Content-Type': 'application/jose'})
        print(f"QR_APPSERVER: [*] Upstream Response: {resp.status_code}")
        
        if resp.status_code != 200:
             return jsonify({"error": "Upstream error", "status": resp.status_code, "body": resp.text}), resp.status_code

        payload_bytes, resp_header = verify_jws(resp.text)
        
        if not validate_jws_headers(resp_header, expected_correlation_id=correlation_id):
             return jsonify({"error": "Security validation failed on upstream response"}), 502

        response_data = json.loads(payload_bytes.decode('utf-8'))
        validate_against_spec(response_data, "PaymentRequest")
        
        return jsonify(response_data)

    except Exception as e:
        print(f"QR_APPSERVER: [!] Error during fetch: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/notify', methods=['POST'])
def notify_payment():
    """
    Proxies the payment notification to the upstream qr_server using JWS.
    Receives a simplified JSON payload, signs it, and returns the verification result.
    """
    data = request.get_json()
    if not data or "id" not in data:
        return jsonify({"error": "Missing id in payload"}), 400
    
    payload_id = data["id"]
    print(f"QR_APPSERVER: [*] Received Notify Request for ID: {payload_id}")

    # Validate input against spec
    validate_against_spec(data, "NotificationPayload")

    # Prepare JWS
    correlation_id = str(uuid.uuid4())
    
    private_key_pem, cert_b64, payer_x5u, payer_thumbprint = load_payer_identity()
    if not private_key_pem:
        return jsonify({"error": "Server identity not configured"}), 500

    iat = int(time.time())
    ttl = (iat * 1000) + 60000
    headers = {
        "alg": "ES256",
        "typ": "payreq+jws",
        "x5u": payer_x5u,
        "kid": "payer-key-id-001",
        "iat": iat,
        "ttl": ttl,
        "correlationId": correlation_id,
        "crit": ["iat", "ttl", "correlationId"]
    }
    
    if USE_X5C:
        headers["x5c"] = [cert_b64]
    else:
        headers["x5t#S256"] = payer_thumbprint

    token = jws.sign(data, private_key_pem, headers=headers, algorithm='ES256')

    notify_url = f"{QR_SERVER_BASE_URL}/notify/{payload_id}"

    try:
        resp = requests.post(notify_url, data=token, headers={'Content-Type': 'application/jose'})
        print(f"QR_APPSERVER: [*] Upstream Response: {resp.status_code}")

        payload_bytes, resp_header = verify_jws(resp.text)
        
        if not validate_jws_headers(resp_header, expected_correlation_id=correlation_id):
             return jsonify({"error": "Security validation failed on upstream response"}), 502

        response_data = json.loads(payload_bytes.decode('utf-8'))
        validate_against_spec(response_data, "SignedStatusCodePayload")
        
        return jsonify(response_data), resp.status_code

    except Exception as e:
        print(f"QR_APPSERVER: [!] Error during notify: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="QR App Server")
    parser.add_argument("--x5c", action="store_true", help="Include x5c header and remove x5t#S256.")
    args = parser.parse_args()
    USE_X5C = args.x5c

    os.makedirs(CACHE_DIR, exist_ok=True)
    print(f"QR_APPSERVER: Starting App Server on port {PORT}...")
    app.run(host='127.0.0.1', port=PORT)