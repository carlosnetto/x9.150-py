# X9.150 QR Code Generator & Payee PSP Simulator (POC)

This repository contains a **Proof of Concept (POC)** and testing implementation of the **ANSI X9.150 QR Code Payments Standard**. It serves two main purposes:
1. **QR Code Generation**: Creates an EMVCo-compliant Merchant Presented Mode QR Code (Section 5.2.2) that references a secure payment payload.
2. **Payee PSP Simulation**: Runs a local server to handle the **Payment Payload Request** (Section 6.2) and the **Payment Notification** (Section 6.3).

## Features

*   **EMVCo Compliance**: Generates QR content strings adhering to EMVCo Merchant Presented Mode specifications (Section 5.2.2).
*   **X9.150 Payload**: Constructs the JSON Payment Payload with required fields (Section 6.2).
*   **Security (JWS)** (Section 7):
    *   Signs outgoing Payment Payloads using `ES256`.
    *   Verifies incoming Payment Notifications using `ES256`.
*   **Explicit Routing**: Uses dedicated paths for payload retrieval (`/fetch/`) and notifications (`/notify/`) instead of a single broker endpoint.
*   **Tunneling Support**: Easily integrates with tunneling services like `pinggy.io` for external device testing.

## Prerequisites

Ensure you have Python 3 installed. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### 1. Generate QR Code & Keys
Run the generator script to create the keys, payment payload, and QR code image. This will also save session data to `x9_data.json`.

```bash
python qr_generator.py templates/01_coffee_shop.json
```

### 2. External Access (e.g., Mobile Scanning)
If you want to scan the QR code with a real mobile device or external app, use a tunneling service (like `ssh -p 443 -R0:localhost:5000 a.pinggy.io`) and pass the domain to the script:

```bash
python payee_server.py --domain <your-domain>.pinggy.io
```

This ensures the QR code contains the correct external URL.

## How It Works

1.  **Startup**: The script generates an ECC key pair (simulating the Payee PSP's keys).
2.  **QR Generation**: It creates a unique Transaction ID and embeds the URL (`https://<domain>/scan/<id>`) into the EMV QR string.
3.  **Image Creation**: Saves the QR code as `qrcode.png`.
4.  **Server**: Starts a Flask server listening for POST requests.

### The "Broker" Logic
The endpoint `/scan/<payload_id>` handles two types of interactions:

1.  **Payment Payload Request**:
    *   **Trigger**: The Payer App scans the QR and sends a POST request containing a JWS with `qrCodeContent`.
    *   **Action**: The server returns the signed Payment Payload (JWS).

2.  **Payment Notification**:
    *   **Trigger**: The Payer PSP sends a POST request containing a JWS with a `payment` object (confirming the transaction).
    *   **Action**: The server verifies the signature using the Payer's public key (simulated) and prints the notification details to the console. It returns a signed JWS with `statusCode: 200`.

## Testing with cURL

Since the server uses a single endpoint, you can simulate the Payer PSP using `curl`.

**1. Request the Payment Payload:**
*(Simulates scanning the QR code)*

```bash
# Replace <URL> with the URL printed by the script
curl -X POST <URL> \
     -H "Content-Type: application/jose" \
     -d 'eyJhbGciOiJFUzI1NiJ9.eyJxckNvZGVDb250ZW50IjoiLi4uIn0.signature'
```

**2. Send a Payment Notification:**
*(Simulates confirming the payment)*

```bash
# Replace <URL> with the URL printed by the script
curl -X POST <URL> \
     -H "Content-Type: application/jose" \
     -d 'eyJhbGciOiJFUzI1NiJ9.eyJwYXltZW50Ijp7ImFtb3VudCI6NDUwMCwiY3VycmVuY3kiOiJVU0QifX0.signature'
```

*Note: The script currently accepts unverified JWS extraction for the purpose of determining the request type in this simulation, but enforces signature verification for the final processing of notifications.*
```