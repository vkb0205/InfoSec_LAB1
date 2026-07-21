# Mini Vault

Mini Vault is a secure secret-management application inspired by HashiCorp Vault.

## Features

- Vault initialization and unlock using a master passphrase
- User registration and login
- Session token authentication
- Encrypted KV secret storage
- Transit encryption/decryption service
- Signing and verification service

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

```bash
python main.py
```

## Test

```bash
pytest
```

## Project Structure

```text
src/core/       # Master passphrase, init/unlock, DEK management
src/auth/       # Register/login, session token, account lockout
src/kv/         # Secure Storage / KV Engine
src/transit/    # Encryption, decryption, signing, verification as a service
src/storage/    # Disk persistence helpers
tests/          # Pytest test cases
data/samples/   # Sample encrypted data and ciphertexts
data/logs/      # Logs, including denied access events
docs/report/    # Final report PDF
```
