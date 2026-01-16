import time
import base64
import json
import uuid
import os
from flask import Flask, jsonify, request
from jose import jws
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# --- CONFIGURATION ---
PORT = 5000
HOST = "127.0.0.1"
PAYLOAD_FILE = "payload.json"

app = Flask(__name__)

# In-memory state (loaded from file)
private_key_pem = None
public_key_pem = None

def load_data():
    """Generates testing keys and prepares the server."""
    global private_key_pem, public_key_pem
    
    # Generate ECC key pair for testing purposes
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if not os.path.exists(PAYLOAD_FILE):
        print(f"[*] Warning: {PAYLOAD_FILE} not found. Ensure qr_generator.py is run.")
    else:
        with open(PAYLOAD_FILE, "r") as f:
            payload_data = json.load(f)
            txn_id = payload_data.get("id")
            if txn_id:
                print(f"[*] Fetch URL:  http://{HOST}:{PORT}/fetch/{txn_id}")
                print(f"[*] Notify URL: http://{HOST}:{PORT}/notify/{txn_id}")
    
    print(f"[*] Testing ECC keys generated.")
    return True

def sign_jws(payload, key_pem):
    """Wraps the payload in a JWS structure (used for responses)."""
    now_ms = int(time.time() * 1000)
    headers = {
        "alg": "ES256",
        "typ": "payresp+jws",
        "x5u": "https://pki.x9.org/certs/payee-psp-cert.pem",
        "x5t#S256": "dummy_thumbprint_base64url",
        "kid": "key-12345",
        "iat": now_ms,
        "ttl": 60000,
        "correlationId": uuid.uuid4().hex,
        "statusCode": "200",
        "crit": ["correlationId", "iat", "ttl", "statusCode"]
    }
    return jws.sign(payload, key_pem, headers=headers, algorithm='ES256')

@app.route('/fetch/<payload_id>', methods=['POST'])
def fetch_payload(payload_id):
    """Endpoint for Payer App to retrieve the Payment Payload (Section 6.2)."""
    if not os.path.exists(PAYLOAD_FILE):
        return jsonify({"error": "Payload file not found"}), 404

    with open(PAYLOAD_FILE, "r") as f:
        payload_data = json.load(f)

    if payload_data.get("id") != payload_id:
        print(f"[!] ID mismatch: Requested {payload_id}, found {payload_data.get('id')}")
        return jsonify({"error": "Payload ID mismatch"}), 404

    print(f"\n[*] Payment Payload Request Received for ID: {payload_id}")
    
    signed_payload = sign_jws(payload_data, private_key_pem)
    return signed_payload, 200, {'Content-Type': 'application/jose'}

@app.route('/notify/<payload_id>', methods=['POST'])
def receive_notification(payload_id):
    """Endpoint for Payer PSP to send Payment Notification (Section 6.3)."""
    if not os.path.exists(PAYLOAD_FILE):
        return jsonify({"error": "No active transaction found"}), 404

    with open(PAYLOAD_FILE, "r") as f:
        payload_data = json.load(f)

    if payload_data.get("id") != payload_id:
        return jsonify({"error": "Transaction ID mismatch"}), 404

    raw_data = request.get_data(as_text=True).strip()

    if raw_data.count('.') == 2:
        try:
            # 1. Verify Signature
            jws.verify(raw_data, public_key_pem, algorithms=['ES256'])

            # 2. Decode Payload
            payload_b64 = raw_data.split('.')[1]
            payload_b64 += '=' * (-len(payload_b64) % 4)
            decoded_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            data = json.loads(decoded_json)

            print(f"\n[!] Payment Notification Received for ID: {payload_id}")
            print(json.dumps(data, indent=2))

            resp_body = {"statusCode": 200}
            signed_resp = sign_jws(resp_body, private_key_pem)
            return signed_resp, 200, {'Content-Type': 'application/jose'}

        except Exception as e:
            print(f"\n[!] Error processing JWS: {e}")
            return jsonify({"error": "Invalid Request or Signature"}), 400

    print(f"\n[!] Invalid Notification Format Received for ID: {payload_id}")
    return jsonify({"error": "Invalid request format. Expected JWS."}), 400

if __name__ == "__main__":
    if load_data():
        print(f"[*] Starting Payee Server at http://{HOST}:{PORT}...")
        app.run(host=HOST, port=PORT, debug=False, use_reloader=False)