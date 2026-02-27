# Developed in Jan 2026, author carlos.netto@gmail.com.
# Purpose: Validate the X9.150 specification.
# Not for production use; intended only to prove the spec.

import sys
import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, utils
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

def find_files(folder):
    """Find the *_key.pem and *.jwks files in a folder."""
    key_file = None
    jwks_file = None
    for f in os.listdir(folder):
        if f.endswith("_key.pem"):
            key_file = os.path.join(folder, f)
        elif f.endswith(".jwks"):
            jwks_file = os.path.join(folder, f)
    return key_file, jwks_file

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <folder>")
        print(f"  The folder must contain a *_key.pem and a *.jwks file.")
        sys.exit(1)

    folder = sys.argv[1]
    if not os.path.isdir(folder):
        print(f"Error: '{folder}' is not a directory.")
        sys.exit(1)

    key_file, jwks_file = find_files(folder)

    if not key_file:
        print(f"Error: No *_key.pem file found in '{folder}'.")
        sys.exit(1)
    if not jwks_file:
        print(f"Error: No *.jwks file found in '{folder}'.")
        sys.exit(1)

    print(f"Folder:      {folder}")
    print(f"Private Key: {os.path.basename(key_file)}")
    print(f"JWKS:        {os.path.basename(jwks_file)}")

    # Load private key
    with open(key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Load certificate from JWKS x5c
    with open(jwks_file, "r") as f:
        jwks = json.load(f)

    key_entry = jwks["keys"][0]
    x5c = key_entry.get("x5c", [])
    if not x5c:
        print("Error: No x5c certificate chain in JWKS.")
        sys.exit(1)

    cert_der = base64.b64decode(x5c[0])
    cert = x509.load_der_x509_certificate(cert_der)
    public_key = cert.public_key()

    # Identify key type
    is_rsa = key_entry.get("kty") == "RSA"
    is_ec = key_entry.get("kty") == "EC"
    alg = key_entry.get("alg", "unknown")

    print(f"Key Type:    {key_entry.get('kty')}")
    print(f"Algorithm:   {alg}")
    print(f"Key ID:      {key_entry.get('kid', 'N/A')}")
    print(f"Certificate: {cert.subject.rfc4514_string()}")

    # Verify thumbprint
    thumbprint_expected = key_entry.get("x5t#S256")
    if thumbprint_expected:
        thumbprint_actual = base64.urlsafe_b64encode(
            hashlib.sha256(cert_der).digest()
        ).rstrip(b"=").decode("ascii")
        thumb_ok = thumbprint_expected == thumbprint_actual
        print(f"Thumbprint:  {'MATCH' if thumb_ok else 'MISMATCH'}")
        if not thumb_ok:
            print(f"  Expected: {thumbprint_expected}")
            print(f"  Actual:   {thumbprint_actual}")
    else:
        print(f"Thumbprint:  not present in JWKS")

    # Generate random payload (10 KB)
    payload = os.urandom(10240)
    payload_hash = hashlib.sha256(payload).hexdigest()[:16]
    print(f"\nTest Payload: 10,240 bytes (SHA-256: {payload_hash}...)")

    # Sign
    print("Signing:     ", end="", flush=True)
    try:
        if is_rsa:
            signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        elif is_ec:
            signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        else:
            print(f"UNSUPPORTED key type: {key_entry.get('kty')}")
            sys.exit(1)
        print(f"OK ({len(signature)} bytes)")
    except Exception as e:
        print(f"FAILED — {e}")
        sys.exit(1)

    # Verify
    print("Verifying:   ", end="", flush=True)
    try:
        if is_rsa:
            public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        elif is_ec:
            public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        print("OK")
    except Exception as e:
        print(f"FAILED — {e}")
        sys.exit(1)

    # Tamper test — flip one bit in the payload and verify it fails
    print("Tamper test: ", end="", flush=True)
    tampered = bytearray(payload)
    tampered[0] ^= 0x01
    try:
        if is_rsa:
            public_key.verify(signature, bytes(tampered), padding.PKCS1v15(), hashes.SHA256())
        elif is_ec:
            public_key.verify(signature, bytes(tampered), ec.ECDSA(hashes.SHA256()))
        print("FAILED — tampered payload was accepted (this should not happen)")
        sys.exit(1)
    except Exception:
        print("OK (tampered payload correctly rejected)")

    print(f"\nResult: PASS — key pair is valid")

if __name__ == "__main__":
    main()
