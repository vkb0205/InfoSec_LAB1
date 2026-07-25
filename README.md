# Mini Vault

Mini Vault is a course project for secure secret storage and cryptographic
operations inspired by HashiCorp Vault.

## Current status

Person 1 Day 1 is implemented:

- Base package and report/data directory structure
- Standard-library CLI skeleton
- Shared application error contract
- JSON storage decision and atomic JSON repository
- Environment and dependency templates
- Day 1 smoke and contract tests

Vault initialization, authentication, KV encryption, and Transit operations are
planned work; they are not represented as complete yet.

## Architecture decisions

The application uses a layered design:

```text
CLI (main.py)
      |
core / auth / kv / transit services
      |
JSON repository (src/storage/)
      |
data/*.json
```

JSON was selected for persistence because it is easy to inspect during the
security demo. The planned runtime files are:

| File | Purpose |
|---|---|
| `data/vault.json` | KDF metadata and encrypted DEK |
| `data/users.json` | Password hashes and account state |
| `data/kv_secrets.json` | Encrypted KV records |
| `data/transit_keys.json` | Encrypted named-key records |

The repository only serializes JSON. Service layers are responsible for making
sure plaintext DEKs, passwords, secrets, AES keys, and private signing keys are
never passed to persistence. Writes use a temporary file followed by atomic
replacement to avoid partially written JSON.

## Setup

Python 3.10 or newer is recommended.

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

On Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

## Run the Day 1 skeleton

```bash
python main.py
python main.py health
python main.py interfaces
```

The `interfaces` command publishes the method signatures that the three team
members will implement on later days.

## Test

The Day 1 suite can run without third-party packages:

```bash
python -m unittest discover -s tests -v
```

After development dependencies are installed, the same tests can be run with:

```bash
python -m pytest
```

## Project structure

```text
src/core/       # Master passphrase, init/unlock, DEK management
src/auth/       # Registration, login, sessions, account lockout
src/kv/         # Encrypted KV storage and path ownership
src/transit/    # Encryption/decryption and signing/verification
src/storage/    # Atomic JSON persistence
tests/          # Automated tests
data/samples/   # Submission-safe encrypted samples
data/logs/      # Access-denial logs
docs/report/    # Report sources, diagrams, screenshots, final PDF
```
