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

def pay_usdc_on_base(mnemonic, recipient_address, amount_to_pay):
    """Connects to Base and sends the specified amount of USDC."""
    # Base Mainnet RPC
    w3 = Web3(Web3.HTTPProvider("https://mainnet.base.org"))
    
    if not w3.is_connected():
        print("[!] Could not connect to Base network.")
        return None, None

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
    
    # amount_to_pay is expected in the token's smallest units (e.g., 6 decimals for USDC)
    recipient = Web3.to_checksum_address(recipient_address)
    nonce = w3.eth.get_transaction_count(account.address)
    
    print(f"[*] Preparing transaction from {account.address} to {recipient}")
    print(f"[*] Amount: {amount_to_pay / 1_000_000:.6f} USDC")
    
    try:
        txn = contract.functions.transfer(recipient, amount_to_pay).build_transaction({
            'chainId': 8453,
            'gas': 100000,
            'gasPrice': w3.eth.gas_price,
            'nonce': nonce,
        })
        
        signed_txn = w3.eth.account.sign_transaction(txn, private_key=account.key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        tx_hex = w3.to_hex(tx_hash)

        print(f"[*] USDC Payment Submitted! Hash: {tx_hex}")
        print(f"[*] Waiting for confirmation on Base blockchain...")

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt['status'] == 1:
            print(f"[OK] Transaction confirmed in block {receipt['blockNumber']}!")
            print(f"[*] View on Explorer: https://basescan.org/tx/{tx_hex}")
            return tx_hex, account.address
        else:
            print(f"[!] Transaction failed on-chain (Status: 0).")
            print(f"[*] View on Explorer: https://basescan.org/tx/{tx_hex}")
            return None, None

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

def validate_jws_headers(header, expected_correlation_id=None):
    """Validates iat, ttl, correlationId, and crit list in JWS headers."""
    # 1. Check 'crit' enforcement (RFC 7515)
    crit = header.get("crit", [])
    if not isinstance(crit, list):
        crit = []
        
    for field in crit:
        if field not in header:
            print(f"[!] Security Error: Critical header '{field}' is missing from response.")
            return False

    # 2. Validate correlationId (Non-repudiation)
    if expected_correlation_id:
        received_id = header.get("correlationId")
        if received_id != expected_correlation_id:
            print(f"[!] Security Error: correlationId mismatch! Expected {expected_correlation_id}, got {received_id}")
            return False

    # 3. Validate iat (Issued At)
    now = int(time.time())
    iat = header.get("iat")
    if iat:
        if iat > now + 60: # 1 minute clock skew allowance
            print("[!] Security Error: iat is in the future!")
            return False
        if now - iat > 480: # 8 minutes threshold
            print(f"[!] Security Error: iat is too old ({now - iat} seconds ago)!")
            return False
    
    # 4. Validate ttl (Time To Live)
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
        print("[!] Testing Mode: Intentionally corrupting the signature (modifying the signature string).")
        parts = token.split('.')
        # Modify the last character of the signature part to invalidate it
        sig = parts[2]
        corrupted_sig = sig[:-1] + ('0' if sig[-1] != '0' else '1')
        return f"{parts[0]}.{parts[1]}.{corrupted_sig}"
        
    return token

def log_server_error(resp):
    """Logs server error, parsing JWS if present for better debugging."""
    content = resp.text.strip()
    if content.count('.') == 2:
        try:
            header = jws.get_unverified_header(content)
            claims = jws.get_unverified_claims(content)
            if isinstance(claims, bytes):
                claims = claims.decode('utf-8')
            
            try:
                payload = json.loads(claims)
            except:
                payload = claims
            
            parts = content.split('.')
            debug_info = {
                "header": header,
                "payload": payload,
                "signature": parts[2]
            }
            print(json.dumps(debug_info, indent=2))
            return
        except:
            pass
    print(content)

def run_payer(fail_sig=False, fail_jws_custom=False, fail_iat=False, fail_ttl=False):
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
    if fail_iat:
        print("[!] Testing Mode: Intentionally sending an iat from 11 minutes ago.")
        iat -= 660

    ttl = (iat * 1000) + 60000  # 1 minute TTL in milliseconds
    if fail_ttl:
        print("[!] Testing Mode: Intentionally sending an expired ttl.")
        ttl = (int(time.time()) * 1000) - 1000

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

    signed_jws = sign_jws_with_fail_logic(payload, private_key_pem, headers)

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
            
            # Validate security headers and correlationId
            if not validate_jws_headers(resp_header, expected_correlation_id=correlation_id):
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
            usdc_amount = 0
            for pm in payload_json.get("paymentMethods", []):
                if pm.get("currency") == "USDC":
                    networks = pm.get("networks", {})
                    if "Base" in networks:
                        usdc_base_address = networks["Base"].get("address")
                        usdc_amount = pm.get("amount", 0)
                        break
            
            if usdc_base_address:
                wallet_file = "wallet_keys.txt"
                if os.path.exists(wallet_file):
                    with open(wallet_file, "r") as f:
                        mnemonic = " ".join([line.strip() for line in f if line.strip()])
                    
                    print(f"\n[*] USDC (Base) payment method detected.")

                    # Dividing the requested amount by 100 for testing purposes 
                    # to reduce actual cost while validating the flow.
                    test_amount = int(usdc_amount / 100)

                    # Derive address for notification
                    Account.enable_unaudited_hdwallet_features()
                    account = Account.from_mnemonic(mnemonic)
                    payer_addr = account.address

                    # --- Step 1: Initial Payment Notification (Initiation) ---
                    print("[*] Initiating payment (Status: PAYMENT_INITIATED)...")
                    notification_payload = {
                        "id": payload_json.get("id"),
                        "payment": {
                            "amount": test_amount,
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

                    signed_init_notification = jws.sign(notification_payload, private_key_pem, headers=headers, algorithm='ES256')
                    
                    notify_url = payload_json.get("paymentNotification")
                    init_resp = requests.post(notify_url, data=signed_init_notification, headers={'Content-Type': 'application/jose'})

                    if init_resp.status_code == 200:
                        init_payload_bytes, init_resp_header = verify_jws(init_resp.text)
                        
                        if not validate_jws_headers(init_resp_header, expected_correlation_id=correlation_id):
                            return

                        init_resp_data = json.loads(init_payload_bytes.decode('utf-8'))
                        validate_against_spec(init_resp_data, "SignedStatusCodePayload")
                        if init_resp_data.get("statusCode") == 200:
                            print("[*] Payee will accept the payment and the qr code is locked to avoid duplicated payment.")
                            
                            # --- Blockchain Payment Step ---
                            tx_hash, _ = pay_usdc_on_base(mnemonic, usdc_base_address, test_amount)

                            if tx_hash:
                                # --- Step 2: Final Payment Notification (Completion) ---
                                print("[*] Sending final notification (Status: PAID) with transaction hash...")
                                notification_payload["payment"]["transactionId"] = tx_hash
                                validate_against_spec(notification_payload, "NotificationPayload")
                                
                                signed_final_notification = jws.sign(notification_payload, private_key_pem, headers=headers, algorithm='ES256')
                                final_resp = requests.post(notify_url, data=signed_final_notification, headers={'Content-Type': 'application/jose'})
                                if final_resp.status_code == 200:
                                    final_payload_bytes, final_resp_header = verify_jws(final_resp.text)
                                    
                                    if not validate_jws_headers(final_resp_header, expected_correlation_id=correlation_id):
                                        return

                                    final_resp_data = json.loads(final_payload_bytes.decode('utf-8'))
                                    validate_against_spec(final_resp_data, "SignedStatusCodePayload")
                                    if final_resp_data.get("statusCode") == 200:
                                        print("[*] Final confirmation received and verified.")
                    else:
                        print(f"[!] Payee initiation failed (Status {init_resp.status_code}):")
                        log_server_error(init_resp)
                else:
                    print(f"\n[!] USDC method available but {wallet_file} not found.")
        else:
            print(f"[!] Error from server:")
            log_server_error(response)
            
    except Exception as e:
        print(f"[!] Request failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="X9.150 Payer PSP Simulator")
    parser.add_argument("--failSignature", action="store_true", help="Intentionally corrupt the JWS signature for testing.")
    parser.add_argument("--failjwscustom", action="store_true", help="Intentionally omit mandatory JWS headers (iat, ttl, correlationId) randomly.")
    parser.add_argument("--failiat", action="store_true", help="Intentionally send an iat from 11 minutes ago.")
    parser.add_argument("--failttl", action="store_true", help="Intentionally send an expired ttl.")
    args = parser.parse_args()

    run_payer(fail_sig=args.failSignature, fail_jws_custom=args.failjwscustom, fail_iat=args.failiat, fail_ttl=args.failttl)