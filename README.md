<!-- Developed in Jan 2026, author carlos.netto@gmail.com. -->
<!-- Purpose: Validate the X9.150 specification. -->
<!-- Not for production use; intended only to prove the spec. -->
# X9.150 Secure Payment QR Code POC

This POC shows how the new **ANSI X9.150 QR code payment standard** can work securely in the real world. It proves how the X9 digital certificate can be leveraged to prevent fake or tampered QR codes, ensuring both sides of the transaction can trust each other.

The main purpose of this Proof of Concept (POC) is to demonstrate that a bank or merchant can trust a QR code payment because the parties are cryptographically verified using digital certificates defined by the X9 standard.

### The Problem It Solves
One of the biggest concerns with QR code payments is: **“How do I know this QR code and this payment request are legitimate?”**

This POC shows:
*   **Payee Identity**: How the payee side proves its identity using an X9 digital certificate.
*   **Payer Verification**: How the payer side can verify that the payment request is authentic and the details have not been altered.
*   **Mutual Trust**: How the payee can verify that the payment confirmation really came from a trusted payment services provider.

This creates a mutual trust model where both sides can verify each other before any money moves.

### POC Explained
The POC simulates a complete end-to-end flow:
1.  **Merchant**: Generates a QR code for a payment.
2.  **Customer**: Scans it with a bank app.
3.  **Secure Retrieval**: The bank app sends a **digitally signed request** to fetch the payment details. The merchant server verifies the requester's digital certificate before returning the JSON payload, ensuring that unauthorized third parties cannot retrieve sensitive transaction data.
4.  **Verification**: The bank app verifies the merchant’s identity using an X9 digital certificate and ensures payment details were not changed.
5.  **Approval**: The customer approves the payment.
6.  **Confirmation**: The merchant system verifies that the payment confirmation came from a trusted, certified party.

*Note: In this POC, while we enforce certificate-based authentication for all participants, we are not strictly validating the root CA against a formal X9 hierarchy; we use a simulated PKI environment to demonstrate the protocol logic.*

This demonstrates **end-to-end identity, authenticity, and integrity**—not just a simple QR code.

### Why This Matters
This proves that QR code payments can be open, interoperable, and secure, and that the industry can have a shared trust framework based on X9 digital certificates.

## Features

*   **EMVCo Compliance**: Generates QR content strings adhering to EMVCo Merchant Presented Mode specifications (Section 5.2.2).
*   **X9.150 Payload**: Constructs the JSON Payment Payload with required fields (Section 6.2).
*   **Security (JWS)** (Section 7):
    *   Signs outgoing payloads and notifications using `ES256`.
    *   Supports **Hybrid Verification**: Uses `x5c` (embedded certificate) for performance and `x5u` (URL-based) for standard-compliant certificate retrieval.
*   **Explicit Routing**: Uses dedicated paths for payload retrieval (`/fetch/`) and notifications (`/notify/`) instead of a single broker endpoint.
*   **Tunneling Support**: Easily integrates with tunneling services like `pinggy.io` for external device testing.
*   **Certificate Server**: Includes a dedicated service to host public keys and JWKS metadata.
*   **Blockchain Integration**: Payer simulation supports USDC payments on the Base network.

## Prerequisites

Ensure you have Python 3 installed. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### 1. Generate Keys and Certificates
First, generate the necessary ECC key pairs, self-signed certificates, and JWKS metadata for both the Payer and Payee.

```bash
python keygen.py
```

### 2. Start the Certificate Server
Run the certificate server to host the public certificates. This allows the JWS `x5u` header to function correctly during verification.

```bash
python certserv.py
```

### 3. Generate QR Code & Payload
Run the generator script with a biller template to create the payment payload, raw QR string, and QR code image.

```bash
python qr_generator.py templates/01_coffee_shop.json
```

### 2. External Access (e.g., Mobile Scanning)
If you want to scan the QR code with a real mobile device or external app, use a tunneling service (like `ssh -p 443 -R0:localhost:5000 a.pinggy.io`) and pass the domain to the script:

```bash
python qr_server.py --domain <your-domain>.pinggy.io
```

This ensures the QR code contains the correct external URL.

### Testing Options

The Payee Server (`qr_server.py`) and Payer Simulator (`qr_payer.py`) support specific flags for testing error handling:

*   `--failCorrelationId`: When enabled, the server will intentionally return a mismatched `correlationId` in the JWS protected header. This allows testing the Payer's non-repudiation and session tracking validation logic.
*   `--failiat`: When enabled, the server will return an `iat` (Issued At) timestamp from 11 minutes ago, triggering the Payer's "too old" security check.
*   `--failttl`: When enabled, the server will return a JWS that is already expired based on the `ttl` (Time To Live) header.
*   `--failSignature`: When enabled, the component will intentionally corrupt the JWS signature (simulating a calculation error) to test the recipient's signature verification logic.
*   `--failjwscustom`: (Payer only) Randomly omits one or more mandatory JWS headers (`iat`, `ttl`, `correlationId`) to test server-side validation of critical headers.
*   `--sanctionedWallet`: (Server only) Specifies a blockchain address to block. If a payment notification is received from this address, the server returns a 403 error, simulating a sanctions hit.

### Specification Documentation

To facilitate the mapping between the technical OpenAPI specification and the X9.150 documentation, use the `dump_open_api.py` utility:

```bash
python3 dump_open_api.py spec/openapi.yaml
```
This generates `openapi_flattened.csv`, providing a flattened view of all JSON paths, mandatory requirements, regex patterns, and data constraints.

## How It Works

1.  **Startup**: The script generates an ECC key pair (simulating the Payee PSP's keys).
2.  **QR Generation**: It creates a unique Transaction ID and embeds the URL (`https://<domain>/fetch/<id>`) into the EMV QR string.
3.  **Image Creation**: Saves the QR code as `qrcode.png`.
4.  **Server**: Starts a Flask server listening for POST requests.

### API Endpoints
The server provides two primary endpoints for the payment flow:

1.  **Payment Payload Request (`/fetch/<payload_id>`)**:
    *   **Trigger**: The Payer App scans the QR and sends a POST request containing a JWS with `qrCodeContent`.
    *   **Action**: The server returns the signed Payment Payload (JWS).

2.  **Payment Notification (`/notify/<payload_id>`)**:
    *   **Trigger**: The Payer PSP sends a POST request containing a JWS with a `payment` object (confirming the transaction).
    *   **Action**: The server verifies the signature using the Payer's public key (simulated) and prints the notification details to the console. It returns a signed JWS with `statusCode: 200`.

## Testing with cURL

You can simulate the Payer PSP using `curl` against the specific endpoints.

**1. Request the Payment Payload:**
*(Simulates scanning the QR code)*

```bash
# Replace <URL> with the URL printed by the script
curl -X POST <URL> \
     -H "Content-Type: application/jose" \
     -d '<header>.<payload-with-qrCodeContent-base64url>.<signature>'
```

**2. Send a Payment Notification:**
*(Simulates confirming the payment)*

```bash
# Replace <URL> with the URL printed by the script
curl -X POST <URL> \
     -H "Content-Type: application/jose" \
     -d '<header>.<payload-with-paymentNotification>.<signature>'
```

*Note: The script currently accepts unverified JWS extraction for the purpose of determining the request type in this simulation, but enforces signature verification for the final processing of notifications.*
```