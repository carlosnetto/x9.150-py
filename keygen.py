# Developed in Jan 2026, author carlos.netto@gmail.com.
# Purpose: Validate the X9.150 specification.
# Not for production use; intended only to prove the spec.

import os
import json
import base64
import hashlib
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID

def bytes_to_base64url(data: bytes) -> str:
    """Helper to convert bytes to base64url encoding as required by JWK."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def generate_key_pair(name, cert_url_base):
    print(f"Generating keys for {name}...")

    # 1. Generate ECC Private Key (P-256 curve)
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    # 2. Save Private Key to local filesystem
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{name}_key.txt", "wb") as f:
        f.write(private_pem)

    # 3. Create a Self-Signed Certificate
    # This is needed for the x5u (URL) and x5t (thumbprint) fields
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{name}.example.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).sign(private_key, hashes.SHA256())

    # Save Certificate as PEM (to be served by certserv.py later)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(f"{name}_cert.pem", "wb") as f:
        f.write(cert_pem)

    # 4. Calculate SHA256 Thumbprint (x5t#S256)
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    thumbprint = hashlib.sha256(cert_der).digest()
    x5t_s256 = bytes_to_base64url(thumbprint)

    # 5. Extract Public Key components for JWK (x and y coordinates)
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    x = bytes_to_base64url(public_numbers.x.to_bytes(32, 'big'))
    y = bytes_to_base64url(public_numbers.y.to_bytes(32, 'big'))

    # 6. Construct the JWKS
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "use": "sig",
        "kid": f"{name}-key-id-001", # Unique identifier for the key
        "x5u": f"{cert_url_base}/{name}_cert.pem",
        "x5t#S256": x5t_s256,
        "alg": "ES256"
    }

    jwks = {"keys": [jwk]}

    with open(f"{name}.jwks", "w") as f:
        json.dump(jwks, f, indent=4)

    print(f"Successfully created {name}_key.txt, {name}_cert.pem, and {name}.jwks")

if __name__ == "__main__":
    # Arbitrary local URL for the certificate server
    BASE_URL = "http://127.0.0.1:5001"
    
    generate_key_pair("payee", BASE_URL)
    generate_key_pair("payer", BASE_URL)
