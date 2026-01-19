# Developed in Jan 2026, author carlos.netto@gmail.com.
# Purpose: Validate the X9.150 specification by parsing the EMV QR content.
# Not for production use; intended only to prove the spec.

import os
import re

# --- CONFIGURATION ---
QR_TEXT_FILE = "qrcode.txt"

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

# EMV Tag Definitions and Basic Validation Rules
TAG_INFO = {
    "00": {"desc": "Payload Format Indicator", "min_len": 2, "max_len": 2, "pattern": r"^01$"},
    "01": {"desc": "Point of Initiation Method", "min_len": 2, "max_len": 2, "pattern": r"^(11|12)$"},
    "26": {"desc": "Merchant Account Information (X9.150)", "min_len": 1, "max_len": 99},
    "52": {"desc": "Merchant Category Code (MCC)", "min_len": 4, "max_len": 4, "pattern": r"^\d{4}$"},
    "53": {"desc": "Transaction Currency", "min_len": 3, "max_len": 3, "pattern": r"^\d{3}$"},
    "54": {"desc": "Transaction Amount", "min_len": 1, "max_len": 13, "pattern": r"^\d+\.\d{2}$"},
    "58": {"desc": "Country Code", "min_len": 2, "max_len": 2, "pattern": r"^[A-Z]{2}$"},
    "59": {"desc": "Merchant Name", "min_len": 1, "max_len": 25},
    "60": {"desc": "Merchant City", "min_len": 1, "max_len": 15},
    "63": {"desc": "CRC", "min_len": 4, "max_len": 4, "pattern": r"^[0-9A-F]{4}$"}
}

SUBTAG_INFO = {
    "26": {
        "00": {"desc": "Global Unique Identifier", "pattern": r"^org\.x9$"},
        "01": {"desc": "Payment URL"}
    }
}

def validate_field(tag, value, parent_tag=None):
    """Validates the value against EMV/X9.150 constraints."""
    info = None
    if parent_tag and parent_tag in SUBTAG_INFO:
        info = SUBTAG_INFO[parent_tag].get(tag)
    else:
        info = TAG_INFO.get(tag)
    
    if not info:
        return True, "N/A"
    
    # Check length constraints
    if "min_len" in info and len(value) < info["min_len"]:
        return False, f"ERR: Too short (min {info['min_len']})"
    if "max_len" in info and len(value) > info["max_len"]:
        return False, f"ERR: Too long (max {info['max_len']})"
    
    # Check pattern
    if "pattern" in info and not re.match(info["pattern"], value):
        return False, f"ERR: Format mismatch"
    
    return True, "OK"

def parse_tlv(data, parent_tag=None):
    """Parses EMV TLV data and returns a list of field dictionaries."""
    results = []
    i = 0
    while i < len(data):
        if i + 4 > len(data):
            break
        tag = data[i:i+2]
        try:
            length = int(data[i+2:i+4])
        except ValueError:
            break
        
        value = data[i+4:i+4+length]
        
        desc = ""
        if parent_tag and parent_tag in SUBTAG_INFO:
            desc = SUBTAG_INFO[parent_tag].get(tag, {}).get("desc", "Unknown Subtag")
        else:
            desc = TAG_INFO.get(tag, {}).get("desc", "Unknown Tag")
            
        is_valid, msg = validate_field(tag, value, parent_tag)
        
        results.append({
            "tag": tag,
            "length": length,
            "value": value,
            "description": desc,
            "is_valid": is_valid,
            "validation_msg": msg
        })
        
        i += 4 + length
    return results

def main():
    if not os.path.exists(QR_TEXT_FILE):
        print(f"[!] Error: {QR_TEXT_FILE} not found. Run qr_generator.py first.")
        return

    with open(QR_TEXT_FILE, "r") as f:
        qr_content = f.read().strip()

    print("="*110)
    print(f"EMV QR PARSER - X9.150 VALIDATOR")
    print("="*110)
    print(f"Raw Content: {qr_content}\n")

    # 1. CRC Validation
    if len(qr_content) < 8 or qr_content[-8:-4] != "6304":
        print("[!] Error: CRC tag (6304) not found at the expected position.")
    else:
        data_to_crc = qr_content[:-4]
        expected_crc = qr_content[-4:]
        calculated_crc = calculate_crc(data_to_crc)
        
        if calculated_crc == expected_crc:
            print(f"[OK] CRC-16/CCITT-FALSE Valid: {calculated_crc}")
        else:
            print(f"[!] CRC Mismatch: Calculated {calculated_crc}, Found {expected_crc}")

    # 2. Field Parsing and Display
    fields = parse_tlv(qr_content)
    
    print(f"\n{'TAG':3}.  | {'LEN':3} | {'VALID':12} | {'DESCRIPTION':40} | {'VALUE'}")
    print("-" * 110)
    
    for field in fields:
        status = "[OK]" if field['is_valid'] else f"[{field['validation_msg']}]"
        print(f"{field['tag']:3}   | {field['length']:02}  | {status:12} | {field['description']:40} | {field['value']}")
        
        # Handle nested tags for Tag 26 (Merchant Account Information)
        if field['tag'] == "26":
            subfields = parse_tlv(field['value'], parent_tag="26")
            for sub in subfields:
                sub_status = "[OK]" if sub['is_valid'] else f"[{sub['validation_msg']}]"
                print(f"26.{sub['tag']:2} | {sub['length']:02}  | {sub_status:12} | {sub['description']:40} | {sub['value']}")

    print("="*110)

if __name__ == "__main__":
    main()