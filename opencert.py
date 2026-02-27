# Developed in Jan 2026, author carlos.netto@gmail.com.
# Purpose: Validate the X9.150 specification.
# Not for production use; intended only to prove the spec.

import sys
import json
import base64
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
import hashlib

def format_hex(data):
    """Format bytes as colon-separated hex string."""
    return ":".join(f"{b:02X}" for b in data)

def print_cert(cert, index, label):
    """Print detailed certificate information."""
    pub = cert.public_key()
    pub_numbers = pub.public_numbers()
    key_size = pub.key_size
    cert_der = cert.public_bytes(Encoding.DER)
    sha256 = hashlib.sha256(cert_der).digest()
    sha1 = hashlib.sha1(cert_der).digest()

    print(f"\n{'='*70}")
    print(f"  [{index}] {label}")
    print(f"{'='*70}")
    print(f"  Subject:       {cert.subject.rfc4514_string()}")
    print(f"  Issuer:        {cert.issuer.rfc4514_string()}")
    print(f"  Serial Number: {format_hex(cert.serial_number.to_bytes((cert.serial_number.bit_length() + 7) // 8, 'big'))}")
    print(f"  Not Before:    {cert.not_valid_before_utc}")
    print(f"  Not After:     {cert.not_valid_after_utc}")
    print(f"  Key Algorithm: RSA {key_size}-bit" if hasattr(pub_numbers, 'n') else f"  Key Algorithm: EC {pub.curve.name}")
    print(f"  Signature:     {cert.signature_algorithm_oid._name}")

    # Fingerprints
    print(f"  SHA-256:       {format_hex(sha256)}")
    print(f"  SHA-1:         {format_hex(sha1)}")

    # Extensions
    for ext in cert.extensions:
        oid = ext.oid.dotted_string
        name = ext.oid._name
        critical = " (CRITICAL)" if ext.critical else ""

        if isinstance(ext.value, x509.BasicConstraints):
            ca = ext.value.ca
            pathlen = ext.value.path_length
            pathlen_str = f", pathlen:{pathlen}" if pathlen is not None else ""
            print(f"  Extension:     {name}{critical} — CA:{ca}{pathlen_str}")
        elif isinstance(ext.value, x509.KeyUsage):
            usages = []
            if ext.value.digital_signature: usages.append("Digital Signature")
            if ext.value.key_cert_sign: usages.append("Certificate Sign")
            if ext.value.crl_sign: usages.append("CRL Sign")
            if ext.value.key_encipherment: usages.append("Key Encipherment")
            if ext.value.content_commitment: usages.append("Content Commitment")
            print(f"  Extension:     {name}{critical} — {', '.join(usages)}")
        elif isinstance(ext.value, x509.SubjectKeyIdentifier):
            print(f"  Extension:     Subject Key ID — {format_hex(ext.value.digest)}")
        elif isinstance(ext.value, x509.AuthorityKeyIdentifier):
            if ext.value.key_identifier:
                print(f"  Extension:     Authority Key ID — {format_hex(ext.value.key_identifier)}")
        elif isinstance(ext.value, x509.ExtendedKeyUsage):
            ekus = [eku.dotted_string for eku in ext.value]
            print(f"  Extension:     Extended Key Usage{critical} — {', '.join(ekus)}")
        elif isinstance(ext.value, x509.CertificatePolicies):
            policies = [p.policy_identifier.dotted_string for p in ext.value]
            print(f"  Extension:     Certificate Policies{critical} — {', '.join(policies)}")
        elif isinstance(ext.value, x509.AuthorityInformationAccess):
            for desc in ext.value:
                print(f"  Extension:     AIA — {desc.access_method._name}: {desc.access_location.value}")
        elif isinstance(ext.value, x509.CRLDistributionPoints):
            for dp in ext.value:
                for name_entry in dp.full_name:
                    print(f"  Extension:     CRL — {name_entry.value}")
        else:
            print(f"  Extension:     {oid}{critical} ({name})")

    # Self-signed check
    if cert.subject == cert.issuer:
        print(f"  Self-Signed:   Yes (Root CA)")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <jwks_file>")
        sys.exit(1)

    jwks_path = sys.argv[1]

    with open(jwks_path, "r") as f:
        jwks = json.load(f)

    key = jwks["keys"][0]
    x5c = key.get("x5c", [])

    if not x5c:
        print("No x5c certificate chain found in the JWKS.")
        sys.exit(1)

    print(f"JWKS file: {jwks_path}")
    print(f"Key ID:    {key.get('kid', 'N/A')}")
    print(f"Algorithm: {key.get('alg', 'N/A')}")
    print(f"Key Type:  {key.get('kty', 'N/A')}")
    print(f"Chain:     {len(x5c)} certificate(s)")

    labels = ["LEAF (End Entity)"]
    for i in range(1, len(x5c)):
        labels.append("INTERMEDIATE CA" if i < len(x5c) - 1 else "ROOT CA")
    if len(x5c) == 1:
        labels = ["LEAF (End Entity)"]

    for i, cert_b64 in enumerate(x5c):
        cert_der = base64.b64decode(cert_b64)
        cert = x509.load_der_x509_certificate(cert_der)
        print_cert(cert, i + 1, labels[i])

    # Verify chain linkage
    print(f"\n{'='*70}")
    print("  Chain Verification")
    print(f"{'='*70}")
    certs = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in x5c]
    all_ok = True
    for i in range(len(certs) - 1):
        child = certs[i]
        parent = certs[i + 1]
        linked = child.issuer == parent.subject
        status = "OK" if linked else "BROKEN"
        if not linked:
            all_ok = False
        print(f"  [{i+1}] {child.subject.rfc4514_string()}")
        print(f"      issued by [{i+2}] {parent.subject.rfc4514_string()} — {status}")
    if certs[-1].subject == certs[-1].issuer:
        print(f"  [{len(certs)}] {certs[-1].subject.rfc4514_string()} — SELF-SIGNED ROOT")
    print(f"\n  Chain linkage: {'VALID' if all_ok else 'BROKEN'}")

if __name__ == "__main__":
    main()
