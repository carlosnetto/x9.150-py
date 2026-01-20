# Developed in Jan 2026, author carlos.netto@gmail.com.
# Purpose: Test utility for qr_appserver.py.

import argparse
import requests
import json
import os

PORT = 5010
HOST = "127.0.0.1"
BASE_URL = f"http://{HOST}:{PORT}"
QR_DIR = "payer_db/qrs"

def test_generate(template_path):
    if not os.path.exists(template_path):
        print(f"QR_APPSERVER_TEST: [!] Error: Template file '{template_path}' not found.")
        return

    try:
        with open(template_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"QR_APPSERVER_TEST: [!] Error decoding JSON from '{template_path}': {e}")
        return
    except Exception as e:
        print(f"QR_APPSERVER_TEST: [!] Error reading file '{template_path}': {e}")
        return

    url = f"{BASE_URL}/generate"
    print(f"QR_APPSERVER_TEST: [*] Sending POST request to {url} with template: {template_path}")
    
    try:
        response = requests.post(url, json=data)
        print(f"QR_APPSERVER_TEST: [*] Status Code: {response.status_code}")
        
        try:
            resp_json = response.json()
            print("QR_APPSERVER_TEST: [*] Response Body:")
            print(json.dumps(resp_json, indent=4))
        except json.JSONDecodeError:
            print("QR_APPSERVER_TEST: [*] Response Body (Text):")
            print(response.text)
            
    except requests.exceptions.ConnectionError:
        print(f"QR_APPSERVER_TEST: [!] Error: Could not connect to {url}. Is qr_appserver.py running?")
    except Exception as e:
        print(f"QR_APPSERVER_TEST: [!] Error during request: {e}")

def test_fetch(qr_input):
    # Check if input is a file
    if os.path.exists(qr_input):
        try:
            with open(qr_input, 'r') as f:
                qr_content = f.read().strip()
            print(f"QR_APPSERVER_TEST: [*] Loaded QR content from file: {qr_input}")
        except Exception as e:
            print(f"QR_APPSERVER_TEST: [!] Error reading file '{qr_input}': {e}")
            return
    else:
        qr_content = qr_input
        print(f"QR_APPSERVER_TEST: [*] Using provided QR content string")

    url = f"{BASE_URL}/fetch"
    payload = {"qrCodeContent": qr_content}
    
    print(f"QR_APPSERVER_TEST: [*] Sending POST request to {url}")
    
    try:
        response = requests.post(url, json=payload)
        print(f"QR_APPSERVER_TEST: [*] Status Code: {response.status_code}")
        
        try:
            resp_json = response.json()
            print("QR_APPSERVER_TEST: [*] Response Body:")
            print(json.dumps(resp_json, indent=4))
        except json.JSONDecodeError:
            print("QR_APPSERVER_TEST: [*] Response Body (Text):")
            print(response.text)
            
    except requests.exceptions.ConnectionError:
        print(f"QR_APPSERVER_TEST: [!] Error: Could not connect to {url}. Is qr_appserver.py running?")
    except Exception as e:
        print(f"QR_APPSERVER_TEST: [!] Error during request: {e}")

def run_interactive_fetch():
    if not os.path.exists(QR_DIR):
        print(f"QR_APPSERVER_TEST: [!] Error: {QR_DIR} not found. Run qr_generator.py first.")
        return

    while True:
        raw_files = [f for f in os.listdir(QR_DIR) if f.endswith(".txt")]
        if not raw_files:
            print(f"QR_APPSERVER_TEST: [!] No QR files found in {QR_DIR}.")
            return

        # Sort by modification time
        raw_files.sort(key=lambda x: os.path.getmtime(os.path.join(QR_DIR, x)))

        print("\nAvailable QR Codes:")
        for i, f in enumerate(raw_files, 1):
            print(f"{i}. {f}")

        choice = input("\nSelect a QR code to fetch (q to quit): ").strip()
        if choice.lower() == 'q':
            break

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(raw_files):
                selected_file = os.path.join(QR_DIR, raw_files[idx])
                test_fetch(selected_file)
            else:
                print(f"QR_APPSERVER_TEST: [!] Invalid selection.")
        except ValueError:
            print("QR_APPSERVER_TEST: [!] Invalid input.")

def test_notify(json_input):
    if not os.path.exists(json_input):
        print(f"QR_APPSERVER_TEST: [!] Error: Input file '{json_input}' not found.")
        return

    try:
        with open(json_input, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"QR_APPSERVER_TEST: [!] Error reading JSON file: {e}")
        return

    url = f"{BASE_URL}/notify"
    print(f"QR_APPSERVER_TEST: [*] Sending POST request to {url}")
    
    try:
        response = requests.post(url, json=data)
        print(f"QR_APPSERVER_TEST: [*] Status Code: {response.status_code}")
        
        try:
            resp_json = response.json()
            print("QR_APPSERVER_TEST: [*] Response Body:")
            print(json.dumps(resp_json, indent=4))
        except json.JSONDecodeError:
            print("QR_APPSERVER_TEST: [*] Response Body (Text):")
            print(response.text)
            
    except Exception as e:
        print(f"QR_APPSERVER_TEST: [!] Error during request: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test utility for QR App Server")
    parser.add_argument("--generate", help="Path to the biller JSON template to generate a QR code")
    parser.add_argument("--fetch", nargs='?', const="interactive", help="QR content string or path to file containing QR content. If flag is present without args, enters interactive mode.")
    parser.add_argument("--notify", help="Path to JSON file containing notification details")
    
    args = parser.parse_args()

    if args.generate:
        test_generate(args.generate)
    elif args.fetch:
        if args.fetch == "interactive":
            run_interactive_fetch()
        else:
            test_fetch(args.fetch)
    elif args.notify:
        test_notify(args.notify)
    else:
        parser.print_help()