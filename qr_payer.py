# Developed in Jan 2026, author carlos.netto@gmail.com.
# Purpose: Validate the X9.150 specification.
# Not for production use; intended only to prove the spec.

import base64
import json
import os
import requests
import uuid
import time
import argparse
import random
from datetime import datetime, timezone
from jose import jws
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from web3 import Web3
from eth_account import Account
import yaml
from jsonschema import Draft7Validator
import referencing
from referencing.jsonschema import DRAFT7

# --- CONFIGURATION ---
QR_TEXT_FILE = "qrcode.txt"
FAIL_SIGNATURE = False
FAIL_JWS_CUSTOM = False

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

def extract_fetch_url(emv_str):
    """Extracts the URL from Tag 26, Subtag 01. URLs shall adhere to RFC 3986."""
    # Top level parsing
    tags = parse_emv_tlv(emv_str)
    if "26" not in tags:
        raise ValueError("Tag 26 (Merchant Account Information) not found in QR content.")
    
    # Sub-tag parsing for Tag 26
    subtags = parse_emv_tlv(tags["26"])
    if "01" not in subtags:
        raise ValueError("Subtag 01 (URL) not found within Tag 26.")
    
    url = subtags["01"]
    # Tag 26 Subtag 01 omits the protocol and the '://' separator to save space.
    # For testing purposes, we are using http:// instead of https:// for simplicity.
    # NOTE: This is NOT compliant with the X9.150 spec, which assumes https://.
    if not url.startswith("http"):
        url = "http://" + url
    return url

def load_payer_identity():
    """Loads the persistent Payer keys and prepares the x5c header."""
    try:
        with open("payer_key.txt", "rb") as f:
            private_pem = f.read()
        
        with open("payer_cert.pem", "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)
            # x5c requires DER format, then standard Base64 encoding
            cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode('utf-8')
            
        # Load x5u from JWKS to include in our own headers
        with open("payer.jwks", "r") as f:
            jwks = json.load(f)
            x5u = jwks["keys"][0].get("x5u")
            
        return private_pem, cert_b64, x5u
    except FileNotFoundError:
        print("[!] Error: Payer keys/certs not found. Run keygen.py first.")
        return None, None, None

def display_payload(payload):
    """Prints the X9.150 payload in a human-readable format."""
    # 1. Basic QR Elements
    print("\n" + "="*60)
    print("QR CODE BASIC ELEMENTS")
    print("="*60)
    skip_keys = ["qrCodeContent", "paymentNotification", "creditor", "bill", "paymentMethods", "additionalInformation", "unstructured"]
    for k, v in payload.items():
        # Note: If validUntil has passed, the Payer PSP should attempt to fetch the payload again.
        # The Payee may provide a new revision with updated adjustments (like late fees) 
        # and an extended validUntil.
        if k not in skip_keys:
            print(f"{k:25}: {v}")

    # 2. Creditor & Ultimate Creditor Information
    creditor = payload.get("creditor", {})
    if creditor:
        print("\n" + "="*60)
        print("CREDITOR INFORMATION")
        print("="*60)
        print(f"{'FIELD':35} | {'VALUE'}")
        print("-" * 60)
        for k, v in creditor.items():
            if k == "address":
                for addr_k, addr_v in v.items():
                    print(f"{f'address.{addr_k}':35} | {addr_v}")
            elif k != "ultimateCreditor":
                print(f"{k:35} | {v}")

        ult_creditor = creditor.get("ultimateCreditor", {})
        if ult_creditor:
            print("\n" + "="*60)
            print("ULTIMATE CREDITOR INFORMATION")
            print("="*60)
            print(f"{'FIELD':35} | {'VALUE'}")
            print("-" * 60)
            for k, v in ult_creditor.items():
                if k == "address":
                    for addr_k, addr_v in v.items():
                        print(f"{f'address.{addr_k}':35} | {addr_v}")
                elif k == "account":
                    for acc_k, acc_v in v.items():
                        print(f"{f'account.{acc_k}':35} | {acc_v}")
                else:
                    print(f"{k:35} | {v}")

    # 3. Bill Details
    bill = payload.get("bill", {})
    amt_due = bill.get("amountDue", {})
    bill_currency = amt_due.get("currency")
    
    print("\n" + "="*60)
    print("BILL DETAILS")
    print("="*60)
    print(f"Description:    {bill.get('description', 'N/A')}")
    print(f"Payment Timing: {bill.get('paymentTiming', 'N/A')}")
    print(f"Amount Due:     {amt_due.get('amount')} {bill_currency}")
    
    adjustments = amt_due.get("adjustments", [])
    if adjustments:
        print("\n" + "="*60)
        print("ADJUSTMENTS")
        print("="*60)
        print(f"{'EXPLANATION':45} | {'AMOUNT':10} | {'VALID UNTIL'}")
        print("-" * 60)
        for adj in adjustments:
            # Note: validUntil is the last millisecond the adjustment is valid.
            # If the current time exceeds this, the Payer PSP must fetch the payload again
            # to ensure adjustments (like late fees or expired discounts) are up to date.
            valid_until = adj.get('validUntil', 'N/A')
            print(f"{adj.get('explanation', ''):45} | {adj.get('amount', ''):10} | {valid_until}")

    tip = bill.get("tip", {})
    if tip.get("allowed"):
        print("\n" + "="*60)
        print("TIP OPTIONS (ENABLED)")
        print("="*60)
        print(f"{'FIELD':35} | {'VALUE'}")
        print("-" * 60)
        print(f"{'Allowed':35} | {tip.get('allowed')}")
        
        range_data = tip.get("range", {})
        if range_data:
            print(f"{'Range (Min / Max)':35} | {range_data.get('min', 'N/A')} / {range_data.get('max', 'N/A')}")
            
        presets = tip.get("presets", [])
        if presets:
            print(f"{'Presets':35} | {', '.join(map(str, presets))}")

    # 4. Unstructured Data
    if "unstructured" in payload:
        print(f"\nUnstructured Data (Metadata): {payload['unstructured']}")

    # 5. Additional Information (Table Format)
    add_info = payload.get("additionalInformation", [])
    if add_info:
        print("\n" + "="*60)
        print(f"{'ADDITIONAL INFORMATION KEY':35} | {'VALUE'}")
        print("-" * 60)
        for item in add_info:
            print(f"{item.get('key', ''):35} | {item.get('value', '')}")

    # 6. Payment Methods
    print("\n" + "="*60)
    print("PAYMENT METHODS & NETWORKS")
    print("="*60)
    for pm in payload.get("paymentMethods", []):
        pm_curr = pm.get("currency")
        print(f"\nCurrency: {pm_curr}")
        if pm_curr != bill_currency and "validUntil" in pm:
            print(f"Conversion rate valid until: {pm['validUntil']}")
        
        print(f"Amount:   {pm.get('amount')}")
        if "editable" in pm:
            print(f"Editable: {json.dumps(pm['editable'])}")
        
        print(f"\n{'NETWORK':15} | {'DETAILS'}")
        print("-" * 60)
        for net, details in pm.get("networks", {}).items():
            detail_str = ", ".join([f"{dk}: {dv}" for dk, dv in details.items()])
            print(f"{net:15} | {detail_str}")

def pay_usdc_on_base(mnemonic, recipient_address):
    """Connects to Base and sends 1 USDC."""
    # Base Mainnet RPC
    w3 = Web3(Web3.HTTPProvider("https://mainnet.base.org"))
    
    if not w3.is_connected():
        print("[!] Could not connect to Base network.")
        return

    # Enable mnemonic features
    Account.enable_unaudited_hdwallet_features()
    account = Account.from_mnemonic(mnemonic)
    
    # USDC Contract on Base
    usdc_address = Web3.to_checksum_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
    usdc_abi = [
        {
            "constant": False,
            "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}],
            "name": "transfer",
            "outputs": [{"name": "", "type": "bool"}],
            "type": "function"
        }
    ]
    
    contract = w3.eth.contract(address=usdc_address, abi=usdc_abi)
    
    # 1 USDC = 1,000,000 units (6 decimals)
    # Paying just 1 USDC for testing purposes and lack of balance enough
    amount_to_pay = 1000000 
    
    recipient = Web3.to_checksum_address(recipient_address)
    nonce = w3.eth.get_transaction_count(account.address)
    
    print(f"[*] Preparing transaction from {account.address} to {recipient}...")
    
    try:
        txn = contract.functions.transfer(recipient, amount_to_pay).build_transaction({
            'chainId': 8453,
            'gas': 100000,
            'gasPrice': w3.eth.gas_price,
            'nonce': nonce,
        })
        
        signed_txn = w3.eth.account.sign_transaction(txn, private_key=account.key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        
        print(f"[*] USDC Payment Sent! Hash: {w3.to_hex(tx_hash)}")
        print(f"[*] View on Explorer: https://basescan.org/tx/{w3.to_hex(tx_hash)}")
        return w3.to_hex(tx_hash), account.address
    except Exception as e:
        print(f"[!] Blockchain transaction failed: {e}")
        return None, None

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
    """Validates iat and ttl in JWS headers for security and spec compliance."""
    now = int(time.time())
    iat = header.get("iat")
    if iat:
        if iat > now:
            print("[!] Security Error: iat is in the future!")
            return False
        if now - iat > 300: # 5 minutes threshold
            print(f"[!] Security Error: iat is too old ({now - iat} seconds ago)!")
            return False
    
    ttl = header.get("ttl")
    if ttl:
        now_ms = int(time.time() * 1000)
        if now_ms > ttl:
            print(f"[!] Security Error: JWS has expired (ttl: {ttl}, current: {now_ms})!")
            return False
    return True

def sign_jws_with_fail_logic(payload, private_key_pem, headers):
    """Helper to sign JWS with optional intentional signature corruption for testing."""
    token = jws.sign(payload, private_key_pem, headers=headers, algorithm='ES256')
    
    if FAIL_SIGNATURE:
        print("[!] Testing Mode: Intentionally corrupting the signature (skipping first 4 bytes of payload calculation).")
        # We sign a version of the payload missing the first 4 bytes
        # but we package it with the original header and payload.
        p_str = json.dumps(payload) if isinstance(payload, dict) else payload
        wrong_token = jws.sign(p_str[4:] if len(p_str) > 4 else p_str, private_key_pem, headers=headers, algorithm='ES256')
        
        parts = token.split('.')
        wrong_parts = wrong_token.split('.')
        return f"{parts[0]}.{parts[1]}.{wrong_parts[2]}"
        
    return token

def run_payer(fail_sig=False, fail_jws_custom=False):
    global FAIL_SIGNATURE
    FAIL_SIGNATURE = fail_sig
    global FAIL_JWS_CUSTOM
    FAIL_JWS_CUSTOM = fail_jws_custom

    # 1. Read the QR code content (simulating a scan)
    if not os.path.exists(QR_TEXT_FILE):
        print(f"[!] Error: {QR_TEXT_FILE} not found. Run qr_generator.py first.")
        return

    with open(QR_TEXT_FILE, "r") as f:
        qrcode_content = f.read().strip()

    print(f"[*] Scanned QR Content: {qrcode_content}")

    # 2. Extract the endpoint URL from the QR content
    try:
        fetch_url = extract_fetch_url(qrcode_content)
        print(f"[*] Extracted Fetch URL: {fetch_url}")
    except Exception as e:
        print(f"[!] Failed to parse QR content: {e}")
        return

    # 3. Create the JSON payload
    correlation_id = str(uuid.uuid4())
    # The spec requires the qrCodeContent to be Base64URL encoded
    qr_b64url = base64.urlsafe_b64encode(qrcode_content.encode()).decode().rstrip("=")
    payload = {
        "qrCodeContent": qr_b64url
    }
    validate_against_spec(payload, "FetchRequestPayload")

    # 4. Generate keys and sign as JWS
    print("[*] Loading Payer identity and signing request...")
    private_key_pem, payer_cert_b64, payer_x5u = load_payer_identity()
    if not private_key_pem:
        return
    
    iat = int(time.time())
    ttl = (iat * 1000) + 60000  # 1 minute TTL in milliseconds

    # Standard JWS headers for X9.150
    headers = {
        "alg": "ES256",
        "typ": "payreq+jws",
        "x5c": [payer_cert_b64],
        "x5u": payer_x5u,
        "kid": "payer-key-id-001",
        "iat": iat,
        "ttl": ttl,
        "correlationId": correlation_id,
        "crit": ["iat", "ttl", "correlationId"]
    }
    
    if FAIL_JWS_CUSTOM:
        fields = ["iat", "ttl", "correlationId"]
        # Select a random non-empty subset to remove
        to_remove = []
        while not to_remove:
            to_remove = [f for f in fields if random.choice([True, False])]
        
        print(f"[!] Testing Mode: Intentionally omitting JWS headers: {to_remove}")
        for field in to_remove:
            if field in headers:
                del headers[field]

    signed_jws = jws.sign(payload, private_key_pem, headers=headers, algorithm='ES256')

    # 5. Call the fetch method
    print(f"[*] Sending Payment Payload Request to {fetch_url}...")
    try:
        response = requests.post(
            fetch_url,
            data=signed_jws,
            headers={'Content-Type': 'application/jose'}
        )
        
        print(f"[*] Server Response Status: {response.status_code}")
        
        if response.status_code == 200:
            # Verify the server's signature (uses x5c or certserv via x5u)
            payload_bytes, resp_header = verify_jws(response.text)
            
            # Validate security headers
            if not validate_jws_headers(resp_header):
                return

            # Validate correlationId echo for non-repudiation
            if resp_header.get("correlationId") != correlation_id:
                print(f"[!] Security Error: correlationId mismatch! Expected {correlation_id}, got {resp_header.get('correlationId')}")
                return

            payload_json = json.loads(payload_bytes.decode('utf-8'))
            validate_against_spec(payload_json, "PaymentRequest")
            display_payload(payload_json)

            # Ensure the request is ACTIVE before proceeding
            status = payload_json.get("status")
            if status == "PAYMENT_INITIATED":
                print("[!] Error: Somebody else has started the payment of this QR code at the same time.")
                return
            elif status == "PAID":
                print("[!] Error: This QR code has already been paid.")
                return
            elif status != "ACTIVE":
                print(f"[!] Error: Payment request is not ACTIVE (Current Status: {status})")
                return
            
            # --- Blockchain Payment Step ---
            usdc_base_address = None
            for pm in payload_json.get("paymentMethods", []):
                if pm.get("currency") == "USDC":
                    networks = pm.get("networks", {})
                    if "Base" in networks:
                        usdc_base_address = networks["Base"].get("address")
                        break
            
            if usdc_base_address:
                wallet_file = "wallet_keys.txt"
                if os.path.exists(wallet_file):
                    with open(wallet_file, "r") as f:
                        mnemonic = " ".join([line.strip() for line in f if line.strip()])
                    
                    print(f"\n[*] USDC (Base) payment method detected.")
                    tx_hash, payer_addr = pay_usdc_on_base(mnemonic, usdc_base_address)

                    if tx_hash:
                        # --- Step 1: Initial Payment Notification (Initiation) ---
                        print("[*] Initiating payment (Status: PAYMENT_INITIATED)...")
                        notification_payload = {
                            "id": payload_json.get("id"),
                            "payment": {
                                "amount": 1000000,  # 1 USDC for testing
                                "currency": "USDC",
                                "network": "BASE",
                                "paymentTiming": payload_json.get("bill", {}).get("paymentTiming")
                                # transactionId omitted for initiation
                            },
                            "payer": {
                                "info": payer_addr,
                                "fromAddress": payer_addr
                            },
                            "expectedDate": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                        }
                        validate_against_spec(notification_payload, "NotificationPayload")

                        signed_init_notification = sign_jws_with_fail_logic(notification_payload, private_key_pem, headers)
                        
                        notify_url = payload_json.get("paymentNotification")
                        init_resp = requests.post(notify_url, data=signed_init_notification, headers={'Content-Type': 'application/jose'})

                        if init_resp.status_code == 200:
                            init_payload_bytes, init_resp_header = verify_jws(init_resp.text)
                            
                            if not validate_jws_headers(init_resp_header):
                                return

                            if init_resp_header.get("correlationId") != correlation_id:
                                print(f"[!] Security Error: correlationId mismatch in init notification! Expected {correlation_id}")
                                return

                            init_resp_data = json.loads(init_payload_bytes.decode('utf-8'))
                            validate_against_spec(init_resp_data, "SignedStatusCodePayload")
                            if init_resp_data.get("statusCode") == 200:
                                print("[*] Payee will accept the payment and the qr code is locked to avoid duplicated payment.")
                            
                            # --- Step 2: Send funds via Base ---
                            tx_hash, _ = pay_usdc_on_base(mnemonic, usdc_base_address)

                            if tx_hash:
                                # --- Step 3: Final Payment Notification (Completion) ---
                                print("[*] Sending final notification (Status: PAID) with transaction hash...")
                                notification_payload["payment"]["transactionId"] = tx_hash
                                validate_against_spec(notification_payload, "NotificationPayload")
                                
                                signed_final_notification = sign_jws_with_fail_logic(notification_payload, private_key_pem, headers)
                                final_resp = requests.post(notify_url, data=signed_final_notification, headers={'Content-Type': 'application/jose'})
                                if final_resp.status_code == 200:
                                    final_payload_bytes, final_resp_header = verify_jws(final_resp.text)
                                    
                                    if not validate_jws_headers(final_resp_header):
                                        return

                                    if final_resp_header.get("correlationId") != correlation_id:
                                        print(f"[!] Security Error: correlationId mismatch in final notification! Expected {correlation_id}")
                                        return

                                    final_resp_data = json.loads(final_payload_bytes.decode('utf-8'))
                                    validate_against_spec(final_resp_data, "SignedStatusCodePayload")
                                    if final_resp_data.get("statusCode") == 200:
                                        print("[*] Final confirmation received and verified.")
                            else:
                                print("[!] Payment failed on-chain. Final notification skipped.")
                        else:
                            print(f"[!] Payee initiation failed: {init_resp.status_code} - {init_resp.text}")
                else:
                    print(f"\n[!] USDC method available but {wallet_file} not found.")
        else:
            print(f"[!] Error from server: {response.text}")
            
    except Exception as e:
        print(f"[!] Request failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="X9.150 Payer PSP Simulator")
    parser.add_argument("--failSignature", action="store_true", help="Intentionally corrupt the JWS signature for testing.")
    parser.add_argument("--failjwscustom", action="store_true", help="Intentionally omit mandatory JWS headers (iat, ttl, correlationId) randomly.")
    args = parser.parse_args()

    run_payer(fail_sig=args.failSignature, fail_jws_custom=args.failjwscustom)