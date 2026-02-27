# CLAUDE.md — Project Conventions for X9.150 POC

## Purpose

X9.150 Secure Payment QR Code Proof of Concept.
Validates the ANSI X9.150 specification with EMVCo QR codes and JWS-based mutual trust.
**Not for production use** — intended only to prove the spec.

## File Map

| File | Description |
|------|-------------|
| `keygen.py` | Generates ECC key pairs, self-signed X.509 certificates, and JWKS metadata for payee and payer |
| `certserv.py` | Flask server (port 5001) hosting public certificates and JWKS endpoints (optional with X9 PKI certs) |
| `qr_server.py` | Payee backend (port 5005) — serves `/fetch/` and `/notify/` endpoints with JWS |
| `qr_payer.py` | Payer/wallet simulator — scans QR, verifies JWS, executes Solana USDC payment |
| `qr_generator.py` | Reads a template, validates against OpenAPI spec (exits on error), builds EMVCo QR string + JSON payload, writes to payee_db/payer_db |
| `qr_parser.py` | Parses and validates EMVCo QR content strings, prints TLV structure |
| `qr_appserver.py` | App developer proxy (port 5010) — plain-JSON gateway that handles JWS internally |
| `qr_delete.py` | Utility to clean up generated QR codes and payloads from the databases |
| `test_data.py` | Generates randomized test payment templates for bulk testing |
| `dump_open_api.py` | Flattens `spec/openapi.yaml` into a CSV with paths, constraints, and regex |
| `opencert.py` | Reads a JWKS file and displays the full `x5c` certificate chain with details and linkage verification |
| `validatepair.py` | Validates that a private key (`*_key.pem`) matches its JWKS certificate — sign/verify test + thumbprint check |
| `qr_appserver_test.py` | Test utility that exercises the app server endpoints |
| `templates/51–54_bad_*.json` | Intentionally invalid templates for spec validation testing |

## Architecture — Three-Server Model

```
certserv (5001)  ←  hosts JWKS / public certs (optional with X9 PKI certs)
qr_server (5005) ←  payee backend (fetch + notify)
qr_appserver (5010) ← app proxy (plain JSON, no JWS for clients)
```

## Data Flow

```
templates/*.json → qr_generator → payee_db/qrs  (server-side payload)
                                 → payer_db/qrs  (QR image + text)

qr_server  ⟵ fetch ⟵  qr_payer (or qr_appserver)
qr_server  ⟵ notify ⟵ qr_payer (or qr_appserver)
```

## Security

- **JWS signing** on every request and response — algorithm read dynamically from JWKS (`alg` field: `ES256` for ECC, `RS256` for RSA)
- **Certificate discovery** (in priority order):
  1. **`x5t#S256`** thumbprint — local cache lookup
  2. **`x5c`** header — certificate chain embedded in JWS (RFC 7515), used by X9 Financial PKI certificates
  3. **`jku`** header — fetches JWKS from certserv (used by self-signed ECC certs from `keygen.py`)
- **`iat` / `ttl`** headers enforce freshness (replay-attack prevention)
- **`correlationId`** in protected header for non-repudiation and session tracking
- **`crit`** header lists mandatory-to-understand custom claims

## Blockchain (Solana)

- Library: `solana-py` + `solders`
- BIP44 derivation path: `m/44'/501'/0'/0'`
- Payment: USDC SPL token via `transfer_checked`
- RPC endpoint: `https://api.mainnet-beta.solana.com` (publicnode.com)
- Wallet: 12-word mnemonic stored in `wallet_keys.txt` (one word per line)

## Python Version

**Use Python 3.13** (latest stable). Python 3.14+ is not supported — `coincurve` (a dependency of `bip-utils`) fails to build on 3.14 due to a missing LICENSE file in the cffi distribution during wheel building.

```bash
python3.13 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## How to Run

```bash
# 1. Generate keys and certificates
python keygen.py

# 2. Start certificate server (only needed with self-signed ECC certs)
python certserv.py

# 3. Start payee server
python qr_server.py

# 4. Generate a QR code
python qr_generator.py templates/01_coffee_shop.json

# 5. Run payer simulation
python qr_payer.py

# Or use the unified startup script:
./start_server.sh
```

## Testing Flags

| Flag | Component | Effect |
|------|-----------|--------|
| `--failSignature` | Server & Payer | Corrupts JWS signature to test verification |
| `--failiat` | Server | Returns `iat` from 11 minutes ago to trigger freshness check |
| `--failttl` | Server | Returns an already-expired JWS based on `ttl` |
| `--failjwscustom` | Payer | Randomly omits mandatory JWS headers (`iat`, `ttl`, `correlationId`) |
| `--failCorrelationId` | Server | Returns mismatched `correlationId` to test non-repudiation |
| `--sanctionedWallet` | Server | Blocks a specified blockchain address (403 on match) |

## Test Templates (Intentionally Invalid)

Templates 51–54 contain intentional spec violations for testing validation:

| Template | Error Type |
|----------|------------|
| `51_bad_mcc.json` | MCC with letters (`58A2`) — violates `^\d{4}$` |
| `52_bad_protection_type.json` | Invalid enum `clear` — not in `[tokenized, encrypted, plaintext]` |
| `53_bad_phone.json` | Phone missing `+` prefix — violates E.164 pattern |
| `54_bad_amount.json` | Negative amount (`-89`) — violates `minimum: 0` |

## Compatible Wallets

The `qr_appserver.py` proxy is designed to work with external wallet apps (maintained independently):
- **[ybank.me-wallet-solana](https://github.com/carlosnetto/ybank.me-wallet-solana)** — Solana-based wallet
- **[ybank.me-wallet](https://github.com/carlosnetto/ybank.me-wallet)** — Base (EVM) wallet

## Coding Style

- Standard 3-line header comment on every `.py` file (author, purpose, not-for-production)
- Synchronous Python — no async/await
- Flask for all HTTP servers
- No external task runners or build tools — run scripts directly with `python`
