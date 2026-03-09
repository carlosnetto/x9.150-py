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
    *   Signs outgoing payloads and notifications using the algorithm specified in the JWKS (`ES256` for ECC, `RS256` for RSA).
    *   Supports **multiple certificate discovery methods**: `x5c` header (certificate chain embedded in JWS), `jku` (JWK Set URL via certserv), and `x5t#S256` (thumbprint for local caching and pinning).
    *   Compatible with **X9 Financial PKI** RSA certificates and self-signed ECC certificates.
*   **Explicit Routing**: Uses dedicated paths for payload retrieval (`/fetch/`) and notifications (`/notify/`) instead of a single broker endpoint.
*   **Certificate Server**: Includes a dedicated service to host public keys and JWKS metadata (optional when using X9 PKI certificates with `x5c` chains).
*   **Blockchain Integration**: Payer simulation supports USDC payments on the Solana network.

## Prerequisites

Ensure you have Python 3 installed. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### 1. Generate Keys and Certificates
Generate ECC key pairs, self-signed certificates, and JWKS metadata for both the Payer and Payee.
Artifacts are generated into `payee_db/certs` and `payer_db/certs`.
Alternatively, place X9 Financial PKI RSA certificates and JWKS files directly in these directories.

```bash
python keygen.py
```

### 2. Start the Certificate Server (Optional)
Run the certificate server to host the public certificates and JWKS metadata. This allows the JWS `jku` header to function correctly during verification.
It serves files from both `payee_db/certs` and `payer_db/certs`.
**Note**: This step is not required when using X9 PKI certificates — the `x5c` certificate chain is embedded directly in each JWS header.

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

### 4. Solana Wallet Setup (for Payer Simulation)
To run `qr_payer.py` with real blockchain payments, create a `wallet_keys.txt` file containing your 12-word BIP39 mnemonic, **one word per line**:
```
word1
word2
...
word12
```
The wallet needs:
*   **USDC** (SPL token) — to fund the payment amount.
*   **SOL** — a small balance for transaction fees.

The payer derives keys using BIP44 path `m/44'/501'/0'/0'`.

### 6. Testing Options

The Payee Server (`qr_server.py`) and Payer Simulator (`qr_payer.py`) support specific flags for testing error handling:

*   `--failCorrelationId`: When enabled, the server will intentionally return a mismatched `correlationId` in the JWS protected header. This allows testing the Payer's non-repudiation and session tracking validation logic.
*   `--failiat`: When enabled, the server will return an `iat` (Issued At) timestamp from 11 minutes ago, triggering the Payer's "too old" security check.
*   `--failttl`: When enabled, the server will return a JWS that is already expired based on the `ttl` (Time To Live) header.
*   `--failSignature`: When enabled, the component will intentionally corrupt the JWS signature (simulating a calculation error) to test the recipient's signature verification logic.
*   `--failjwscustom`: (Payer only) Randomly omits one or more mandatory JWS headers (`iat`, `ttl`, `correlationId`) to test server-side validation of critical headers.
*   `--sanctionedWallet`: (Server only) Specifies a blockchain address to block. If a payment notification is received from this address, the server returns a 403 error, simulating a sanctions hit.

#### Invalid Templates for Validation Testing

Templates 51–54 contain intentional spec violations to demonstrate how `qr_generator.py` and `qr_payer.py` catch bad payloads:

*   `51_bad_mcc.json` — MCC with letters (`58A2`), violates `^\d{4}$`
*   `52_bad_protection_type.json` — Invalid `protectionType` enum (`clear`)
*   `53_bad_phone.json` — Phone missing `+` prefix, violates E.164
*   `54_bad_amount.json` — Negative amount (`-89`), violates `minimum: 0`

### 7. Specification Documentation

To facilitate the mapping between the technical OpenAPI specification and the X9.150 documentation, use the `dump_open_api.py` utility:

```bash
python3 dump_open_api.py spec/openapi.yaml
```
This generates `openapi_flattened.csv`, providing a flattened view of all JSON paths, mandatory requirements, regex patterns, and data constraints.

## How It Works

### Technical Component Breakdown
To understand the implementation, follow these files in order to see how the X9.150 trust chain is built:

1.  **`keygen.py` (The Trust Setup)**: Generates Elliptic Curve (ECC) keys and self-signed X.509 certificates into `payee_db/certs` and `payer_db/certs`. In X9.150, identity is bound to these certificates. This simulates the enrollment of a Merchant or Bank into the payment network. Alternatively, X9 Financial PKI RSA certificates can be placed directly in these directories.
2.  **`certserv.py` (The Certificate Repository)**: Hosts public certificates and JWKS metadata from the `*_db/certs` folders. When using self-signed ECC certs, the Payer uses the `jku` (JWK Set URL) header to fetch the certificate from this server. When using X9 PKI certificates, this service is not needed — the `x5c` certificate chain is embedded in the JWS header instead.
3.  **`qr_generator.py` (The Merchant POS)**: Creates the EMVCo-compliant QR string. It validates the generated payload against the OpenAPI spec and stops with an error if validation fails. It saves the secure JSON payload to `payee_db/qrs` (for the server) and the QR code to `payer_db/qrs` (for the payer to scan).
4.  **`qr_server.py` (The Payee Backend)**: The core logic. It loads keys from `payee_db/certs` and payloads from `payee_db/qrs`. It manages the `/fetch/` endpoint and the `/notify/` endpoint.
5.  **`qr_payer.py` (The Wallet Simulator)**: Simulates the consumer's banking app. It scans QR codes from `payer_db/qrs` and loads its own identity from `payer_db/certs`. It performs the critical "Verification" step: checking the Merchant's JWS signature and validating the certificate before showing the "Pay" button to the user.
6.  **`qr_appserver.py` (The App Developer Proxy)**: A gateway designed to simplify integration for mobile and web applications. It handles all JWS signing and verification internally, allowing the frontend to communicate using plain JSON.
7.  **`qr_parser.py` (The QR Validator)**: Parses and validates EMVCo QR content strings, printing the TLV (Tag-Length-Value) structure for debugging and spec compliance checks.
8.  **`test_data.py` (The Test Data Generator)**: Generates randomized payment request templates for bulk testing against the OpenAPI schema.
9.  **`opencert.py` (The Certificate Inspector)**: Reads a JWKS file and displays the full `x5c` certificate chain — subject, issuer, extensions, fingerprints, and chain linkage verification. Useful for inspecting X9 Financial PKI certificates.
10. **`validatepair.py` (The Key Pair Validator)**: Validates that a private key file (`*_key.pem`) matches its JWKS certificate by signing and verifying a test payload, and checking the `x5t#S256` thumbprint. Supports both RSA and ECC key types.

## App Server Proxy (`qr_appserver.py`)

The `qr_appserver.py` listens on port **5010**. Its primary purpose is to act as a bridge for mobile apps or webapps that want to implement X9.150 without initially implementing the full JWS (JSON Web Signature) stack. 

### Compatible Wallets
The following wallet apps are designed to work with the App Server. Their source code is maintained independently:
*   **[ybank.me-wallet-solana](https://github.com/carlosnetto/ybank.me-wallet-solana)** — Solana-based wallet
*   **[ybank.me-wallet](https://github.com/carlosnetto/ybank.me-wallet)** — Base (EVM) wallet

To launch the App Server (along with all other servers), use:
```bash
./start_server.sh
```

### ⚠️ Payment Responsibility Disclaimer
The `qr_appserver.py` **does not handle wallets, mnemonics (12 words), or blockchain transactions.**
*   The wallet app is responsible for managing the user's private keys.
*   The wallet app is responsible for executing the actual payment on the blockchain (e.g., Solana) using the details provided in the `PaymentRequest`.
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
            "network": "Solana",
            "transactionId": "5UfDuX..."
        },
        "payer": { "info": "user@email.com", "fromAddress": "7xKX..." },
        "expectedDate": "2025-09-30T18:04:00Z"
    }
    ```
*   **Returns**: The status code and response from the upstream `qr_server` (e.g., `{"statusCode": 200}`).

### The Security Handshake (JWS)
The security of X9.150 relies on **JSON Web Signatures (JWS)**. Every exchange follows this pattern:
*   **Protected Header**: Tells the receiver the signing algorithm (read from JWKS: `ES256` or `RS256`) and how to find the certificate — via `x5c` (embedded chain), `jku` (remote JWKS URL), or `x5t#S256` (cached thumbprint).
*   **Payload**: The actual transaction data (Amount, Currency, Merchant ID).
*   **Signature**: A cryptographic seal. If even one character in the payload is changed (e.g., changing $10.00 to $100.00), the signature verification will fail.

**Note on Freshness**: To prevent replay attacks and ensure security, each JWS contains an `iat` (Issued At) and `ttl` (Time To Live) header. In this POC, the Payer app explicitly refreshes these headers immediately before signing each notification message. This ensures that the message is always "fresh" when it reaches the server, even if the user took several minutes to review and approve the payment details.