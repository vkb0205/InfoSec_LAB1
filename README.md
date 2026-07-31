# Mini Vault

Mini Vault is a secure secret-management application inspired by HashiCorp Vault.

## Features

- Vault initialization and unlock using a strong master passphrase
- Encrypted vault metadata with Argon2id and AES-256-GCM wrapped DEK
- Runtime locked/unlocked vault state that resets to locked after process restart
- CLI and REST (FastAPI) for Feature 0.1–1 — long-lived server keeps unlock across requests
- Locked-vault gates for KV and Transit operations
- User registration and Argon2-protected login
- Process-local, 30-minute session token authentication
- Encrypted KV secret storage with path-ownership ACL (CLI + REST)
- Transit encryption/decryption service (future feature)
- Signing and verification service (future feature)
- DEK-wrapped, owner-bound Transit AES key creation, listing, and revocation
- Transit AES-GCM encryption and authenticated decryption
- Transit named-key ownership enforcement with denied-access logging
- Ed25519 signing and verification with DEK-wrapped private keys
- Encrypted KV secret storage (future feature)

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run

Run commands from the `LAB1/` directory:

```bash
python main.py interactive (or python main.py)
python main.py init
python main.py unlock
python main.py register
python main.py login
python main.py serve
python main.py init-shamir
python main.py unlock-shamir
python main.py enable-mfa
python main.py kv --help
python main.py transit --help
```

### `interactive`

If you prefer not to run individual CLI commands, you can run python main.py interactive (or just python main.py with no arguments) to enter the interactive menu mode. This mode provides a numbered menu (0-14) allowing you to sequentially check status, initialize, unlock, register, login, and directly interact with kv storage or transit encryption features.

### `status`

Prints exactly one state:

- `uninitialized` when vault metadata does not exist
- `locked` when metadata exists but this process has no in-memory DEK
- `unlocked` for an unlocked in-process `Vault` instance

```bash
python main.py status
```

### `init`

Initializes the vault from a clean metadata path. The Master Passphrase is read with `getpass.getpass`; do not pass it as a command-line argument.

```bash
python main.py init
```

Successful initialization writes encrypted metadata to `data/vault_metadata.json` and prints:

```text
initialized
locked
```

The process remains locked after initialization by design.

### `unlock`

Unlocks the vault for the current process using the Master Passphrase prompt:
```bash
python main.py unlock
```

### `init-shamir` and `unlock-shamir`
The application supports Shamir's Secret Sharing for vault initialization and unlocking.

Use python main.py init-shamir to initialize the vault. It will prompt you for the Total Shares (N) and the Threshold (K), then output the generated shares.

To unlock, use python main.py unlock-shamir. The system will prompt you to input the required number of shares (matching the Threshold) to unlock the vault.

A correct passphrase prints `unlocked`. Expected failures print only a stable public error code such as `UNLOCK_FAILED`, `INVALID_INPUT`, or `ALREADY_INITIALIZED`.

### REST API (Feature 0.1 + 0.2)

Long-lived HTTP server. One in-process `Vault` + one `AuthService` — unlock and session tokens survive across requests until the server process exits (then vault locked again; sessions wiped).

```bash
python main.py serve
# optional: python main.py serve --host 127.0.0.1 --port 8000
# or: uvicorn src.api.app:app --host 127.0.0.1 --port 8000
```

| Method | Path | Body / header | Success |
|--------|------|---------------|---------|
| `GET` | `/v1/status` | — | `{"status":"uninitialized"\|"locked"\|"unlocked"}` |
| `POST` | `/v1/init` | `{"passphrase":"..."}` | `{"result":"initialized","status":"locked"}` |
| `POST` | `/v1/unlock` | `{"passphrase":"..."}` | `{"status":"unlocked"}` |
| `POST` | `/v1/auth/register` | `{"email","passphrase","confirmation"}` | `{"result":"registered"}` |
| `POST` | `/v1/auth/login` | `{"email","passphrase"}` | `{"token":"..."}` |
| `GET` | `/v1/auth/session` | `Authorization: Bearer <token>` | `{"email":"..."}` |
| `POST` | `/v1/kv/write` | Bearer + `{"path","data"}` | `{"version","created_at","updated_at"}` |
| `GET` | `/v1/kv/read?path=...` | Bearer; optional `version` | `{"path","data"}` |
| `DELETE` | `/v1/kv/delete?path=...` | Bearer | `{"result":"DELETED_SUCCESSFULLY"}` |

Errors return only a public code, e.g. `{"code":"UNLOCK_FAILED"}`. Passphrases only in JSON body. DEK/KEK/password hashes never in responses. KV paths must be `secret/<email>/...`; token email must match path owner.

Example (PowerShell: use `curl.exe` or `Invoke-RestMethod`):

```bash
curl.exe -s http://127.0.0.1:8000/v1/status
curl.exe -s -X POST http://127.0.0.1:8000/v1/unlock -H "Content-Type: application/json" -d "{\"passphrase\":\"Str0ng!Passphrase123\"}"
curl.exe -s -X POST http://127.0.0.1:8000/v1/auth/register -H "Content-Type: application/json" -d "{\"email\":\"user@example.com\",\"passphrase\":\"Str0ng!Passphrase123\",\"confirmation\":\"Str0ng!Passphrase123\"}"
curl.exe -s -X POST http://127.0.0.1:8000/v1/auth/login -H "Content-Type: application/json" -d "{\"email\":\"user@example.com\",\"passphrase\":\"Str0ng!Passphrase123\"}"
curl.exe -s http://127.0.0.1:8000/v1/auth/session -H "Authorization: Bearer <token-from-login>"
curl.exe -s -X POST http://127.0.0.1:8000/v1/kv/write -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"path\":\"secret/user@example.com/demo\",\"data\":\"my-secret\"}"
curl.exe -s "http://127.0.0.1:8000/v1/kv/read?path=secret/user@example.com/demo" -H "Authorization: Bearer <token>"
curl.exe -s -X DELETE "http://127.0.0.1:8000/v1/kv/delete?path=secret/user@example.com/demo" -H "Authorization: Bearer <token>"
```

### `register` and `login`

Register an account with a canonical email and a strong passphrase. `register` prompts for the passphrase and confirmation and prints `registered` when successful. `login` prompts for the email and passphrase and prints one opaque session token on success. Passphrases must never be command-line arguments.

```bash
python main.py register
python main.py login
```

Tokens are valid only in the issuing process for 30 minutes. Five consecutive incorrect passphrases lock that account for five minutes; failures print only stable codes such as `INVALID_CREDENTIALS` or `ACCOUNT_LOCKED`. Account records are held in `data/users.json`, which is ignored by Git and contains Argon2 verification hashes and lockout state only—never sessions or plaintext passphrases.

### KV Command-Line Interface

In addition to the REST API, Key-Value (KV) features can be accessed directly via the CLI using the `python main.py kv <command>` syntax:
* **Write data:** `python main.py kv write --token <token> --path <path> --secret <secret>`
* **Read data:** `python main.py kv read --token <token> --path <path>`
* **Delete data:** `python main.py kv delete --token <token> --path <path>`

### Transit Command-Line Interface

Encryption and digital signature services can also be accessed via the CLI using the `python main.py transit <command>` syntax:
* **Create AES key:** `python main.py transit create-key --token <token> --key-name <key-name>`
* **Encrypt:** `python main.py transit encrypt --token <token> --key-name <key-name> --plaintext <plaintext>`
* **Decrypt:** `python main.py transit decrypt --token <token> --ciphertext <ciphertext>`
* **Create signing key:** `python main.py transit create-signing-key --token <token> --key-name <key-name>`
* **Sign message:** `python main.py transit sign --token <token> --key-name <key-name> --message <message>`
* **Verify signature:** `python main.py transit verify --token <token> --key-name <key-name> --message <message> --signature <signature>`

### `init-shamir` and `unlock-shamir`

The application supports Shamir's Secret Sharing for vault initialization and unlocking.
* Use `python main.py init-shamir` to initialize the vault. It will prompt you for the Total Shares (N) and the Threshold (K), then output the generated shares.
* To unlock, use `python main.py unlock-shamir`. The system will prompt you to input the required number of shares (matching the Threshold) to unlock the vault.

### `enable-mfa`

The application supports Multi-Factor Authentication (MFA).
* Run `python main.py enable-mfa` to enable it.
* The system will prompt for your `Email` and `Passphrase`, then return a `secret` and a `provisioning_uri` for TOTP setup.
* When MFA is enabled for an account, the `login` command will automatically detect it and prompt for a TOTP Code.


### Transit named keys

`TransitService.create_key`, `list_keys`, and `revoke_key` implement Feature 2.1.
Duplicate names are rejected per owner with `DUPLICATE_KEY`; different owners
may use the same name. Named AES-256 keys are wrapped with the vault DEK before
`data/transit_keys.json` is written. Public results contain only the key name,
usage, and operation status—never key material.

### Transit encryption and decryption

`TransitService.encrypt` accepts base64 plaintext and returns
`vault:<key_name>:<base64(nonce+ciphertext+tag)>`. `TransitService.decrypt`
reads the key name from that envelope, verifies the owner and key usage, and
returns base64 plaintext only after AES-GCM authentication succeeds. Malformed
input, revoked keys, wrong key usage, and modified ciphertext are rejected.

### Transit access control

Only the authenticated owner may encrypt or decrypt with a named key.
Inaccessible and missing keys return the same `PERMISSION_DENIED` error before
the DEK or AES operation is accessed. Each denial appends only the requester
email, denied key name, and event type to `data/logs/access_denied.jsonl`.

### Transit signing and verification

`create_signing_key` creates an Ed25519 key with `SIGN_VERIFY` usage and stores
only its DEK-wrapped private key and public verification key. `sign` and
`verify` require strict base64 input and an explicit `RAW` or `DIGEST` message
type. `RAW` is SHA-256 hashed by the service; `DIGEST` must contain exactly 32 bytes.
Verification returns a structured `signature_valid` result, including `false`
for altered messages, cross-key signatures, and malformed signatures. Only the
key owner may sign or verify.

## Test

Run the full test suite from `LAB1/`:

```bash
pytest
```

Or run only Feature 0.1 tests:

```bash
pytest tests/test_vault_initialization.py tests/test_repository_create_only.py tests/test_vault_unlock.py tests/test_vault_unlock_failures.py tests/test_vault_kdf_bounds.py tests/test_cli_init_unlock.py tests/test_api_vault_0_1.py tests/test_locked_kv_gate.py tests/test_locked_transit_gate.py
```

## Project Structure

```text
src/core/       # Master passphrase, init/unlock, DEK management
src/api/        # FastAPI REST adapter (Feature 0.1–1)
src/auth/       # Register/login, session token, account lockout
src/kv/         # Secure Storage / KV Engine
src/transit/    # Encryption, decryption, signing, verification as a service
src/storage/    # Disk persistence helpers
tests/          # Pytest test cases
data/samples/   # Sample encrypted data and ciphertexts
data/logs/      # Logs, including denied access events
report/         # Report notes and assets
```
