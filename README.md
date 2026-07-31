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
python main.py status
python main.py init
python main.py unlock
python main.py register
python main.py login
python main.py serve
```

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
