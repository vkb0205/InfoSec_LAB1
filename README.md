# Mini Vault

Mini Vault is a course project for secure secret storage and cryptographic
operations inspired by HashiCorp Vault.

## Current status

Person 1 Days 1–2 are implemented:

- Base package and report/data directory structure
- Standard-library CLI skeleton
- Shared application error contract
- JSON storage decision and atomic JSON repository
- Environment and dependency templates
- Strong Master Passphrase validation
- Argon2id key derivation with random salt
- Random 256-bit DEK encrypted by AES-256-GCM
- Locked startup and generic unlock failure behavior
- Day 1 and Day 2 security tests

User authentication, KV encryption, and Transit operations are planned work;
they are not represented as complete yet.

The authoritative assignment requirements are in `Crypt_proj1.md`. `PLAN.md`
defines the three-person implementation schedule.

## Architecture decisions

The application uses a layered design:

```text
CLI (main.py)
      |
live Vault object ------ in-memory plaintext DEK while unlocked
      |
core / auth / kv / transit services
      |
JSON repository (src/storage/)
      |
data/*.json ------------ encrypted key material only
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

### Vault cryptographic design

Initialization uses these choices:

- Master Passphrase policy: 12–128 characters with lowercase, uppercase,
  number, and symbol characters
- KDF: Argon2id with a fresh 128-bit salt
- Production KDF defaults: 3 iterations, 64 MiB memory, parallelism 4
- Generated DEK: 256 random bits
- DEK protection: AES-256-GCM with a fresh 96-bit nonce
- Associated data: a fixed, versioned DEK context string

`encrypted_dek_b64` contains
`base64(nonce || encrypted_DEK || authentication_tag)`. The salt, bounded
Argon2id parameters, and encrypted DEK are persisted; the Master Passphrase,
derived wrapping key, and plaintext DEK are not.

The metadata file always stores `"status": "locked"`. An unlocked state exists
only inside a live `Vault` object, so constructing a new object or restarting
the process always returns to the locked state.

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

## Run

```bash
python main.py
python main.py health
python main.py interfaces
python main.py status
python main.py init
python main.py unlock
```

`init` and `unlock` prompt through `getpass`; the Master Passphrase is never a
command-line argument, printed response, or stored field. Initialization asks
for confirmation and leaves the current `Vault` object unlocked.

Each command above launches a new process. Consequently, `unlock` currently
demonstrates passphrase verification and process-local state, then that state
ends with the process. Later feature commands must reuse the same live `Vault`
object through a long-running CLI session or service process.

The `interfaces` command publishes the method signatures that the team members
will implement on later days.

## Test

```bash
python -m pytest -q
python -m unittest discover -s tests -v
```

The tests use reduced Argon2id costs to keep the suite fast. Runtime code uses
the production defaults above, and the selected parameters are stored with the
encrypted DEK for future unlocks.

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
