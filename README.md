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
Artifacts are generated into `payee_db/certs` and `payer_db/certs`.

```bash
python keygen.py
```

### 2. Start the Certificate Server
Run the certificate server to host the public certificates. This allows the JWS `x5u` header to function correctly during verification.
It serves files from both `payee_db/certs` and `payer_db/certs`.

```bash
python certserv.py
```

### 3. Generate QR Code & Payload
Run the generator script with a biller template to create the payment payload, raw QR string, and QR code image.
*   **Payee Data**: The JSON payload (what the server returns) is saved to `payee_db/qrs`.
*   **Payer Data**: The QR code image and text content (what the user scans) are saved to `payer_db/qrs`.

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

### Technical Component Breakdown
To understand the implementation, follow these files in order to see how the X9.150 trust chain is built:

1.  **`keygen.py` (The Trust Setup)**: Generates Elliptic Curve (ECC) keys and X.509 certificates into `payee_db/certs` and `payer_db/certs`. In X9.150, identity is bound to these certificates. This simulates the enrollment of a Merchant or Bank into the payment network.
2.  **`certserv.py` (The Certificate Repository)**: Hosts public certificates and JWKS metadata from the `*_db/certs` folders. When a Payer receives a signed message, they use the `x5u` (X.509 URL) header to fetch the certificate from this server to verify the signature.
3.  **`qr_generator.py` (The Merchant POS)**: Creates the EMVCo-compliant QR string. It saves the secure JSON payload to `payee_db/qrs` (for the server) and the QR code to `payer_db/qrs` (for the payer to scan).
4.  **`qr_server.py` (The Payee Backend)**: The core logic. It loads keys from `payee_db/certs` and payloads from `payee_db/qrs`. It manages the `/fetch/` endpoint and the `/notify/` endpoint.
5.  **`qr_payer.py` (The Wallet Simulator)**: Simulates the consumer's banking app. It scans QR codes from `payer_db/qrs` and loads its own identity from `payer_db/certs`. It performs the critical "Verification" step: checking the Merchant's JWS signature and validating the certificate before showing the "Pay" button to the user.
6.  **`qr_appserver.py` (The App Developer Proxy)**: A gateway designed to simplify integration for mobile and web applications. It handles all JWS signing and verification internally, allowing the frontend to communicate using plain JSON.

## App Server Proxy (`qr_appserver.py`)

The `qr_appserver.py` listens on port **5010**. Its primary purpose is to act as a bridge for mobile apps or webapps that want to implement X9.150 without initially implementing the full JWS (JSON Web Signature) stack.

### ⚠️ Payment Responsibility Disclaimer
The `qr_appserver.py` **does not handle wallets, mnemonics (12 words), or blockchain transactions.** 
*   The mobile app is responsible for managing the user's private keys.
*   The mobile app is responsible for executing the actual payment on the blockchain (Solana, Ethereum, Base, etc.) using the details provided in the `PaymentRequest`.
*   The app server simply facilitates the secure communication protocol defined by X9.150.

### Exposed APIs

#### 1. Generate QR Content (`/generate`)
Used by a merchant-side app to generate a new QR code string from a template.
*   **Request (POST)**: A JSON Payment Request template (compatible with `openapi.yaml`).
*   **Returns**: 
    ```json
    {
        "qrContent": "00020101021226...",
        "filePath": "payer_db/qrs/..."
    }
    ```

#### 2. Fetch Payment Details (`/fetch`)
Used by a payer-side app after scanning a QR code to get the full, verified payment details.
*   **Request (POST)**: 
    ```json
    { "qrCodeContent": "00020101021226..." }
    ```
*   **Process**: The proxy extracts the URL, signs a JWS request, fetches the data from the merchant's `qr_server`, verifies the merchant's signature, and returns plain JSON.
*   **Returns**: A plain JSON `PaymentRequest` object containing amounts, merchant info, and supported payment networks.

#### 3. Notify Payment (`/notify`)
Used by a payer-side app to inform the merchant that a payment has been initiated or completed.
*   **Request (POST)**:
    ```json
    {
        "id": "transaction-uuid",
        "payment": {
            "amount": 1000,
            "currency": "USDC",
            "network": "Base",
            "transactionId": "0x..." 
        },
        "payer": { "info": "user@email.com", "fromAddress": "0x..." },
        "expectedDate": "2025-09-30T18:04:00Z"
    }
    ```
*   **Returns**: The status code and response from the upstream `qr_server` (e.g., `{"statusCode": 200}`).

### The Security Handshake (JWS)
The security of X9.150 relies on **JSON Web Signatures (JWS)**. Every exchange follows this pattern:
*   **Protected Header**: Tells the receiver which certificate to use (`x5u` or `x5c`) and the algorithm (`ES256`).
*   **Payload**: The actual transaction data (Amount, Currency, Merchant ID).
*   **Signature**: A cryptographic seal. If even one character in the payload is changed (e.g., changing $10.00 to $100.00), the signature verification will fail.

---

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