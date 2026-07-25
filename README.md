# Mini Vault

Mini Vault is a course project for secure secret storage and cryptographic
operations inspired by HashiCorp Vault.

## Current status

Person 1 Days 1–6 are implemented:

- Base package and report/data directory structure
- Standard-library CLI skeleton
- Shared application error contract
- JSON storage decision and atomic JSON repository
- Environment and dependency templates
- Strong Master Passphrase validation
- Argon2id key derivation with random salt
- Random 256-bit DEK encrypted by AES-256-GCM
- Locked startup and generic unlock failure behavior
- User registration and unique normalized email identities
- Argon2id password hashing
- Random 30-minute sessions with only token fingerprints stored
- Persistent five-attempt, exactly five-minute account lockout
- Non-exporting, DEK-backed AES-GCM operations for KV and Transit
- Reusable nonce/ciphertext/tag envelope with strict base64 parsing
- In-process nonce-reuse protection and best-effort DEK memory clearing
- Shared vault/session/ownership request guard
- Append-only JSON Lines logging for cross-owner access denials
- Generic permission errors that do not disclose resource existence
- Day 1–5 security tests
- Day 6 rubric-aligned vault/auth acceptance suite and traceability matrix

KV `write/read/delete` and Transit operations are planned work owned by Person 2
and Person 3; they are not represented as complete yet.

The Day 6 suite proves that the shared request boundary returns `VAULT_LOCKED`
for both KV and Transit request types before session or ownership processing.
The same assertion must also be bound to the concrete feature operations after
Person 2 and Person 3 implement their service classes.

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
| `data/sessions.json` | Hashed session tokens and expiration metadata |
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

### DEK operation contract for KV and Transit

The raw DEK has no getter and must never be returned by an API. Code that needs
DEK protection uses:

```python
envelope = vault.encrypt_with_dek(
    plaintext_bytes,
    associated_data=b"mini-vault:kv:v1:" + path.encode("utf-8"),
)

stored_fields = envelope.to_base64_fields()

restored = AesGcmEnvelope.from_base64_fields(stored_fields)
plaintext = vault.decrypt_with_dek(
    restored,
    associated_data=b"mini-vault:kv:v1:" + path.encode("utf-8"),
)
```

`AesGcmEnvelope` contains only:

```json
{
  "nonce_b64": "...",
  "ciphertext_b64": "...",
  "tag_b64": "..."
}
```

The Vault generates the 96-bit nonce internally and tracks nonces used with the
live DEK to prevent accidental in-process reuse. AAD binds ciphertext to its
intended context: changing the KV path, owner, or named-key identity causes
authentication failure.

`lock()` overwrites the mutable in-memory DEK buffer before releasing it.
Because Python and third-party cryptographic libraries may create immutable
temporary copies internally, this is best-effort memory clearing rather than a
formal zeroization guarantee.

Required order for future KV and Transit operations:

1. `guard.authenticate(token)` checks the live Vault, then the session.
2. Parse or load the resource owner only after authentication succeeds.
3. `guard.require_owner(...)` checks ownership and audits a mismatch.
4. Call the DEK-backed encryption or decryption method.

The low-level `aes_gcm_encrypt` helper accepts an explicit nonce for vault
initialization and tests. Feature services should use `Vault.encrypt_with_dek`
so locked-state and nonce-generation checks cannot be skipped.

### Shared authorization and denial logging

KV and Transit must share the same live service instances:

```python
from src.core import RequestGuard
from src.storage import AccessDeniedLogger

audit = AccessDeniedLogger("data/logs")
guard = RequestGuard(vault, auth, audit)
```

For KV, validate the token before parsing or comparing the owner path:

```python
identity = guard.authenticate(token)
path_owner = parse_validated_secret_path(path)
guard.require_owner(
    identity,
    path_owner,
    operation="read",
    resource_type="kv_path",
    resource_id=path,
)
```

For Transit, use `resource_type="transit_key"` and the denied key name as
`resource_id`. If the owner is already safely available, `authorize_owner()`
combines authentication and ownership validation.

An ownership mismatch is logged before returning the same generic response for
every resource:

```json
{
  "error_code": "PERMISSION_DENIED",
  "message": "Permission denied."
}
```

Audit records are appended to `data/logs/access_denied.jsonl` and contain only:

- UTC timestamp
- requester email
- operation
- resource type (`kv_path` or `transit_key`)
- denied path or key name

The logger cannot accept session tokens, passphrases, plaintext secret data, or
key material. JSON encoding prevents newline-based log injection. If the audit
record cannot be written, authorization fails closed with `AUDIT_ERROR`.

### Authentication design

Registration and login use these choices:

- Emails are trimmed, converted to lowercase, validated, and treated as unique
  identities. This canonical form will also be used in KV owner paths.
- User passphrases follow the same 12–128 character-class policy as the Master
  Passphrase and are hashed using Argon2id with a fresh salt.
- `users.json` stores only the Argon2id hash, failed-attempt count, and UTC
  lockout timestamp. It never stores a user passphrase.
- Login returns a 256-bit random URL-safe session token valid for 30 minutes.
- `sessions.json` stores a SHA-256 fingerprint of that random token, not the raw
  bearer token. SHA-256 is used only for high-entropy tokens; passwords always
  use Argon2id.
- Four consecutive failures return `UNAUTHENTICATED`. The fifth sets
  `locked_until` to exactly five minutes after that attempt and returns
  `ACCOUNT_LOCKED`.
- Correct credentials cannot bypass an active lockout. At the exact expiration
  timestamp the account is available and its failure counter resets.
- Missing, unknown, or expired sessions return `UNAUTHENTICATED`.

`AuthService.validate_session(token)` returns a `SessionIdentity` containing the
normalized owner email. KV and Transit must call it before their ownership
checks.

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
python main.py register --email alice@example.com
python main.py login --email alice@example.com
python main.py validate-session
```

`init` and `unlock` prompt through `getpass`; the Master Passphrase is never a
command-line argument, printed response, or stored field. Initialization asks
for confirmation and leaves the current `Vault` object unlocked.

Each command above launches a new process. Consequently, `unlock` currently
demonstrates passphrase verification and process-local state, then that state
ends with the process. Later feature commands must reuse the same live `Vault`
object through a long-running CLI session or service process.

User session records are persistent, so tokens returned by `login` can be
validated by a later CLI process. Passphrases and tokens are read using
`getpass`; only the newly issued token is returned in the login response.

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
