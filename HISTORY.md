# Changelog

All notable changes to the X9.150 Secure Payment QR Code POC.

## 2026-02-27
- Fix template 10 (steakhouse): add missing `allowed` field in tip, convert range/presets from strings to integers
- Fix template 11 (utility bill): add milliseconds to `dueDate` timestamp, add required `validUntil` to adjustment
- Add intentionally invalid templates 51–54 for spec validation testing (bad MCC, invalid protectionType enum, missing phone `+` prefix, negative amount)
- Make `qr_generator.py` exit with code 1 when OpenAPI spec validation fails instead of continuing to generate QR codes and payloads
- Add explicit `[OK] JWS Signature Verified` log message to `qr_server.py` after successful signature verification on both `/fetch` and `/notify`

## 2026-02-26
- Replace hardcoded ES256 algorithm with dynamic `alg` from JWKS across `qr_server.py`, `qr_payer.py`, and `qr_appserver.py` — supports both ES256 (ECC) and RS256 (RSA) signing
- Add `x5c` certificate chain to JWS protected headers (RFC 7515) and use it as a certificate discovery method in `verify_jws()`, enabling operation without certserv
- Make `jku` conditional — only included in JWS headers when present in JWKS, preventing null URL fetch errors with X9 Financial PKI certificates

## 2026-02-25
- Document Python 3.13 requirement — `coincurve` fails to build on Python 3.14+
- `9fb5293` Update HISTORY.md with latest commits
- `8d81010` Replace qr_app references with external wallet repos in README
- `d94aa1d` Add missing ultimateCreditor account to PayPal and CashApp templates
- `4de4353` Add project docs (CLAUDE.md, HISTORY.md), refresh README, and reduce template amounts to under 2 USDC

## 2026-02-24
- `54a02d3` Replace Base (EVM) USDC payment with Solana in qr_payer.py
- `2922813` Remove qr_app frontend bundle from repository
- `930cb26` Improve error messages and add comment for cents-to-dollars conversion

## 2026-02-23
- `b040263` Update start_server.sh to include Payee Server and add cloudflared-config.yml

## 2026-02-11
- `169c795` Replace pinggy.sh and qr_appserver.sh with unified start_server.sh
- `f24ca52` Fix TTL expiration bug in qr_payer.py by refreshing headers before signing notifications
- `40ffb23` Remove .DS_Store from repository and prevent future tracking

## 2026-01-25
- `e496e5e` docs: Remove detailed API endpoints and testing instructions from README
- `7e05bdb` feat: Add the `qr_app` web application, update the app server script to serve it, and revise README instructions for external access
- `991eb0e` feat: Add `pinggy.sh` and `qr_appserver.sh` scripts, and remove payment timing from `qr_payer.py`
- `3e654d8` feat: Add static file serving to the app server, derive thumbprints from JWKS, and refine key generation with an optional PEM output

## 2026-01-24
- `5d22f02` feat: Update OpenAPI schema to include conditional `invoice` requirements, `minItems` for `additionalInformation`, and enforce required fields in `Tip`, `AdditionalInfo`, and `TipRange`
- `029cc23` feat: Add a test data generation script and refine the OpenAPI schema with new required fields, enum constraints, and improved descriptions

## 2026-01-23
- `a8caee5` Getting prepared for PQC encryption. Using jku and jwks instead of .pem files and xtu. --x5c removed

## 2026-01-22
- `92a9625` Adjusted some templates used to create QR Codes
- `717792c` feat: Enhance max length derivation in `dump_open_api.py` from numeric maximums and integer types, and refine `openapi.yaml` with explicit length and format constraints

## 2026-01-21
- `405bf2a` feat: Display QR code location and modification date in the deletion prompt

## 2026-01-20
- `ece3f3c` feat: Enable CORS for the Flask application and update dependencies
- `23484e3` docs: Add documentation for the new `qr_appserver.py` App Developer Proxy, including its purpose and API endpoints
- `31e85fb` Implemented an "app server" that's a proxy, listening a single port, with no digital signatures or JWS, just to simplify demos using WebUIs or Apps
- `247b79b` feat: Implement certificate caching and conditional `x5c` header inclusion in `qr_server.py` and `qr_payer.py`
- `90b974d` feat: Add BRL Pix payment option to fine dining template and create a utility script to delete generated QR codes
- `cdbb3f7` feat: Add patterns for OS-generated files like `.DS_Store` and `._*`, and re-categorize `.gitignore` entries
- `aeae14e` docs: Update README with explicit file paths for generated artifacts and data loading across scripts
- `5c35b23` refactor: Centralize key and certificate management into dedicated directories and enhance QR code handling with selection and payment confirmation

## 2026-01-19
- `472ff15` docs: Add detailed comments and README explanations for EMV QR, X9.150, and JWS components across the project files
- `24508e7` refactor: Modify signature corruption logic in testing mode to target the first character instead of the last
- `21fc850` docs: Update comment to reflect qr_server port changed from 5000 to 5005
- `fc342b0` Refactor: Reorder payment flow to send initial notification before blockchain transaction and regenerate cryptographic assets. Added simulation of sanctioned wallet trying to pay
- `d891cd7` fixing curl examples on README.md
- `f46e03c` Making curl examples generic
- `03f3926` docs: Enhance end-to-end flow description with a new secure retrieval step and add a note about the simulated PKI environment
- `af63bae` refactor: Enhance OpenAPI schema flattening to CSV with detailed field information and add new regex and length constraints to payment request fields
- `ad7b2b6` .DS_Store added to .gitignore
- `2b5e550` feat: Add an X9.150 EMV QR parser and validator, and update a grocery store template to test merchant name length limits

## 2026-01-18
- `f351256` feat: Increase JWS iat validation threshold to 8 minutes and add options to intentionally send/return invalid iat/ttl for testing
- `c308541` Demo -> POC
- `09dd713` feat: Improve JWS header validation with `crit` and `correlationId` checks, and update README to detail X9.150 security
- `01a6882` feat: Implement JWS header validation for iat, ttl, and crit fields in the QR server and update cryptographic assets
- `ce4964c` refactor: Update JSON schema validation to use `Draft7Validator` and `referencing` for robust `$ref` resolution, correct `oneOf` to `anyOf` in `openapi.yaml`, and add standard file headers
- `7f2b4d7` feat: Include schema descriptions in the flattened OpenAPI CSV output and add the output file to .gitignore
- `06800a8` docs: Add OpenAPI specification documentation and clarify API endpoint details in the README
- `876000f` docs: Corrected script name from `payee_server.py` to `qr_server.py` in README example
- `3b69786` feat: Add OpenAPI specifications for payment requests and notifications, and integrate validation into QR generation and parsing
- `0072458` feat: Add OpenAPI specifications for payment requests and notifications, and integrate validation into QR generation and parsing

## 2026-01-17
- `7b2955e` Renaming files
- `125472c` Fixing 07_designer_paypal.json
- `4484554` README.md updated
- `0ef6068` Created certserv, that responds to http:// in JWS to retrieve the certificate and keygen to generate pair of keys and certificates for both payee and payer

## 2026-01-16
- `1d21f60` Initial commit: X9.150 QR Code POC with Blockchain Integration
