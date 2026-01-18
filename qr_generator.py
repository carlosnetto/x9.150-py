import time
import base64
import uuid
import json
import argparse
import os
import qrcode
from datetime import datetime, timezone, timedelta
import yaml
from jsonschema import validate, RefResolver

# --- CONFIGURATION ---
PORT = 5000
HOST = "127.0.0.1"
BASE_URL = f"http://{HOST}:{PORT}"
QR_TEXT_FILE = "qrcode.txt"
QR_IMAGE_FILE = "qrcode.png"
PAYLOAD_FILE = "payload.json"

# --- DATA PROCESSING ---
def validate_against_spec(data, schema_name):
    """Validates JSON against the OpenAPI spec. Required for spec validation testing."""
    spec_path = os.path.join(os.path.dirname(__file__), "spec", "openapi.yaml")
    if not os.path.exists(spec_path):
        return
    with open(spec_path, 'r') as f:
        spec = yaml.safe_load(f)
    schema = spec['components']['schemas'][schema_name]
    resolver = RefResolver(f"file://{os.path.abspath(spec_path)}", spec)
    try:
        validate(instance=data, schema=schema, resolver=resolver)
        print(f"[OK] Created JSON validated against {schema_name}")
    except Exception as e:
        print(f"[!] Spec Validation Error ({schema_name}): {e}")

CURRENCY_TO_NUMERIC = {
    "USD": "840",
    "EUR": "978",
    "GBP": "826",
    "CAD": "124"
}

def calculate_crc(data_string):
    """Calculates the CRC-16/CCITT-FALSE (0xFFFF, 0x1021) for EMV QR."""
    crc = 0xFFFF
    polynomial = 0x1021
    data_bytes = data_string.encode('utf-8')
    
    for byte in data_bytes:
        crc ^= (byte << 8)
        for _ in range(8):
            if (crc & 0x8000):
                crc = (crc << 1) ^ polynomial
            else:
                crc = crc << 1
            crc &= 0xFFFF
    return f"{crc:04X}"

def format_emv_qr(url, template):
    """Constructs the EMVCo Merchant Presented Mode QR Content String."""
    # Note: url shall adhere to the syntax dictated by RFC 3986.
    def tlv(tag, value):
        return f"{tag}{len(value):02}{value}"

    creditor = template.get("creditor", {})
    bill = template.get("bill", {})
    amt_due = bill.get("amountDue", {})
    address = creditor.get("address", {})

    # Tag 26 Subtag 01 omits the protocol and the '://' separator to save space.
    # For example, 'https://bank.com/fetch/uid' becomes 'bank.com/fetch/uid'.
    # The standard assumes the URL starts with https://.
    clean_url = url.split("://")[-1] if "://" in url else url
    tag_26_val = tlv("00", "org.x9") + tlv("01", clean_url)
    
    amt_decimal = f"{amt_due.get('amount', 0) / 100:.2f}"
    currency_num = CURRENCY_TO_NUMERIC.get(amt_due.get("currency"), "840")
    
    data = [
        tlv("00", "01"),
        tlv("01", "12"),
        tlv("26", tag_26_val),
        tlv("52", creditor.get("MCC", "0000")[:4]),
        tlv("53", currency_num[:3]),
        tlv("54", amt_decimal[:13]),
        tlv("58", address.get("country", "US")[:2]),
        tlv("59", creditor.get("name", "Merchant")[:25]),
        tlv("60", address.get("city", "City")[:15]),
    ]
    
    raw_str = "".join(data) + "6304"
    return raw_str + calculate_crc(raw_str)

def create_payment_payload(template, qr_content_string, payload_id, base_url):
    """Merges Template with System Generated Fields."""
    now = datetime.now(timezone.utc)
    now_str = now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    valid_until = (now + timedelta(minutes=15)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    
    qr_b64 = base64.urlsafe_b64encode(qr_content_string.encode()).decode().rstrip("=")
    
    # 1. Start with system fields to ensure they are at the beginning of the JSON
    payload = {
        "id": payload_id,
        "revision": 0,
        "qrCodeContent": qr_b64,
        "createdAt": now_str,
        "revisedAt": now_str,
        "sentAt": now_str,
        "validUntil": valid_until,
        "status": "ACTIVE",
        "paymentNotification": f"{base_url}/notify/{payload_id}"
    }

    # 2. Merge template fields, handling paymentMethods specifically for key ordering
    for key, value in template.items():
        if key == "paymentMethods":
            updated_methods = []
            for pm in value:
                new_pm = {}
                # Place currency first if it exists
                if "currency" in pm:
                    new_pm["currency"] = pm["currency"]
                
                # Place validUntil right after currency
                new_pm["validUntil"] = valid_until
                
                # Add remaining keys from the template's payment method
                for pm_key, pm_val in pm.items():
                    if pm_key not in ["currency", "validUntil"]:
                        new_pm[pm_key] = pm_val
                updated_methods.append(new_pm)
            payload["paymentMethods"] = updated_methods
        elif key not in payload:
            payload[key] = value

    return payload

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="X9 QR Code Generator")
    parser.add_argument("template", help="Path to the biller JSON template")
    parser.add_argument("domain", nargs="?", help="Optional external domain (e.g. random.pinggy.io)")
    args = parser.parse_args()

    if not os.path.exists(args.template):
        print(f"[!] Error: Template file '{args.template}' not found.")
        exit(1)

    with open(args.template, "r") as f:
        template_data = json.load(f)

    if args.domain:
        BASE_URL = f"https://{args.domain}" if not args.domain.startswith("http") else args.domain.rstrip('/')

    txn_id = uuid.uuid4().hex
    qr_url = f"{BASE_URL}/fetch/{txn_id}"

    print(f"[*] Processing template: {args.template}")
    emv_qr_string = format_emv_qr(qr_url, template_data)
    final_payload = create_payment_payload(template_data, emv_qr_string, txn_id, BASE_URL)

    # Validate the created payload against the spec
    validate_against_spec(final_payload, "PaymentRequest")

    with open(QR_TEXT_FILE, "w") as f:
        f.write(emv_qr_string)
    print(f"[*] Raw QR string saved to '{QR_TEXT_FILE}'.")

    with open(PAYLOAD_FILE, "w") as f:
        json.dump(final_payload, f, indent=4)
    print(f"[*] Final X9.150 payload saved to '{PAYLOAD_FILE}'.")

    print("[*] Generating QR Code Image...")
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(emv_qr_string)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(QR_IMAGE_FILE)
    print(f"[*] QR Code image saved as '{QR_IMAGE_FILE}'.")
