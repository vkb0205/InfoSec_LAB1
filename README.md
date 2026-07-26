# Mini Vault

Mini Vault is a secure secret-management application inspired by HashiCorp Vault.

## Features

- Vault initialization and unlock using a strong master passphrase
- Encrypted vault metadata with Argon2id and AES-256-GCM wrapped DEK
- Runtime locked/unlocked vault state that resets to locked after process restart
- Locked-vault gates for future KV and Transit operations
- User registration and Argon2-protected login
- Process-local, 30-minute session token authentication
- DEK-wrapped, owner-bound Transit AES key creation, listing, and revocation
- Encrypted KV secret storage (future feature)
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

### `register` and `login`

Register an account with a canonical email and a strong passphrase. `register` prompts for the passphrase and confirmation and prints `registered` when successful. `login` prompts for the email and passphrase and prints one opaque session token on success. Passphrases must never be command-line arguments.

```bash
python main.py register
python main.py login
```

Tokens are valid only in the issuing process for 30 minutes. Five consecutive incorrect passphrases lock that account for five minutes; failures print only stable codes such as `INVALID_CREDENTIALS` or `ACCOUNT_LOCKED`. Account records are held in `data/users.json`, which is ignored by Git and contains Argon2 verification hashes and lockout state only—never sessions or plaintext passphrases.

### Transit named keys

`TransitService.create_key`, `list_keys`, and `revoke_key` implement Feature 2.1.
Duplicate names are rejected per owner with `DUPLICATE_KEY`; different owners
may use the same name. Named AES-256 keys are wrapped with the vault DEK before
`data/transit_keys.json` is written. Public results contain only the key name,
usage, and operation status—never key material.

## Test

Run the full test suite from `LAB1/`:

```bash
pytest
```

Or run only Feature 0.1 tests:

```bash
pytest tests/test_vault_initialization.py tests/test_repository_create_only.py tests/test_vault_unlock.py tests/test_vault_unlock_failures.py tests/test_vault_kdf_bounds.py tests/test_cli_init_unlock.py tests/test_locked_kv_gate.py tests/test_locked_transit_gate.py
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
report/         # Report notes and assets
```
