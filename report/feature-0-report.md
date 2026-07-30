# Mini Vault Feature 0 Report: Initialization/Unlock and User Authentication

## Scope

This report summarizes the implemented Feature 0.1 and Feature 0.2 security foundations for Mini Vault:

- **Feature 0.1 — Vault Initialization and Unlock**: creates encrypted vault metadata, keeps the Data Encryption Key (DEK) locked by default, unlocks only with the correct Master Passphrase, and gates protected KV/Transit operations while locked.
- **Feature 0.2 — User Identity Authentication**: supports user registration, Argon2 password verification, process-local sessions, account lockout after repeated failed logins, and authentication ordering for future protected operations.

---

## Feature 0.1 — Vault Initialization and Unlock

### Implemented Components

Feature 0.1 is implemented across these modules:

- `src/crypto_utils.py`
- `src/core/vault.py`
- `src/storage/repository.py`
- `src/kv/service.py`
- `src/transit/service.py`
- `main.py`

### Vault Metadata Format

On first initialization, Mini Vault creates `data/vault_metadata.json`. The metadata is schema-versioned and contains only non-secret KDF/AEAD parameters plus the encrypted DEK envelope:

- `schema_version = 1`
- KDF algorithm: `argon2id`
- 16-byte random salt
- Argon2id parameters: memory cost, time cost, parallelism, hash length
- AEAD algorithm: `aes-256-gcm`
- 12-byte random nonce
- AES-GCM ciphertext and tag containing the wrapped DEK

No plaintext Master Passphrase, plaintext DEK, derived key, or runtime unlock state is persisted.

### Cryptographic Design

The Master Passphrase is validated for strength before any root key material is generated or written. A fresh 32-byte DEK is generated during initialization. The wrapping key is derived from the Master Passphrase with Argon2id, and the DEK is encrypted using AES-256-GCM with fixed metadata associated data.

Unlock reverses this process: the metadata is strictly validated, the wrapping key is derived from the supplied passphrase, and AES-GCM authentication must succeed before the plaintext DEK is stored in memory.

### State Behavior

The vault follows a conservative state model:

- A new `Vault` instance starts without a plaintext DEK.
- If metadata is absent, the vault is uninitialized.
- If metadata exists, the vault starts locked.
- Successful initialization writes metadata but leaves the vault locked.
- Successful unlock stores the DEK only in memory for the current process.
- Restarting the process always loses unlocked state.

### Error Handling

Feature 0.1 exposes stable public error codes only:

- `INVALID_INPUT`
- `ALREADY_INITIALIZED`
- `UNLOCK_FAILED`
- `VAULT_LOCKED`

Malformed metadata, invalid base64, unsupported schema/KDF values, wrong passphrases, and AES-GCM authentication failures all map to `UNLOCK_FAILED` during unlock. CLI paths print only public codes and avoid tracebacks for expected failures.

### Protected Operation Gate

KV and Transit service boundaries enforce the vault locked check before any downstream work. While locked:

- KV `write`, `read`, and `delete` raise `VAULT_LOCKED`.
- Transit `create_key`, `list_keys`, `revoke_key`, `encrypt`, `decrypt`, `create_signing_key`, `sign`, and `verify` raise `VAULT_LOCKED`.

This preserves the required ordering for later features: vault unlock must happen before session validation, ownership checks, parsing, storage access, or cryptography.

---

## Feature 0.2 — User Identity Authentication

### Implemented Components

Feature 0.2 is implemented primarily in:

- `src/auth/service.py`
- `src/storage/repository.py`
- `src/errors.py`
- `main.py`

Supporting behavior is documented in `specs/002-user-auth/`.

### Registration

Users register with:

- email address
- passphrase
- confirmation passphrase

The email is normalized to a canonical lowercase/casefolded form and validated with a basic email pattern. Registration rejects malformed emails, duplicate canonical emails, weak passphrases, and mismatched confirmation values.

User passphrases are never stored directly. The service hashes passphrases using Argon2 through `argon2.PasswordHasher`, and only the password-verification representation is written to the user store.

### User Store

Accounts are stored in `data/users.json` through `UserRepository`. The store is schema-versioned and strictly validated. Each account record contains:

- canonical email
- Argon2 password hash
- consecutive failed login count
- optional UTC `locked_until` timestamp

The user store does not contain plaintext passphrases and does not contain session tokens. Writes use a restricted temporary file and atomic replacement to avoid partial account-store updates.

### Login and Sessions

Login verifies the supplied passphrase against the stored Argon2 hash. On success:

- failed login state is reset
- a fresh opaque session token is generated
- the token is stored only in memory
- the token expires after 30 minutes

Sessions are intentionally process-local. A restarted `AuthService` starts with no active sessions, so previously issued tokens become invalid after restart.

### Lockout Policy

Feature 0.2 implements a five-consecutive-failure account lockout:

- Failed verification increments the account's `failed_attempts` counter.
- On the fifth consecutive failed login, `locked_until` is set to current time plus five minutes.
- Login attempts during the active lockout fail with `ACCOUNT_LOCKED`, even if the correct passphrase is supplied.
- After expiry, a correct login clears the lockout and resets the failure count.
- Failed attempts are account-scoped and do not affect other users.

### Authentication Error Handling

Feature 0.2 adds stable public authentication codes:

- `DUPLICATE_USER`
- `INVALID_CREDENTIALS`
- `ACCOUNT_LOCKED`
- `UNAUTHENTICATED`

The implementation avoids exposing passphrases, hashes, tokens, storage paths, or verification internals through normal errors or CLI output.

### Protected Operation Ordering

Feature 0.2 preserves the Feature 0.1 boundary. Protected KV and Transit operations must first check whether the vault is unlocked. Only after that should session validation occur. This means:

1. Locked vault -> `VAULT_LOCKED`
2. Unlocked vault but missing/invalid/expired token -> `UNAUTHENTICATED`
3. Valid session -> identity is available for future ownership authorization

---

## CLI Summary

The CLI supports prompt-based operations:

```bash
python main.py init
python main.py status
python main.py unlock
python main.py register
python main.py login
```

Sensitive inputs are accepted with `getpass` prompts rather than command-line arguments. Successful registration prints `registered`. Successful login prints a single session token. Expected failures print only public error codes.

---

## Security Review Summary

The implementation follows these security decisions:

- Master Passphrases and user passphrases are never persisted.
- Vault DEK is persisted only after AES-GCM wrapping.
- Plaintext DEK exists only in memory after successful unlock.
- Runtime vault unlock state is never written to disk.
- Session tokens are never persisted.
- Account lockout state is persisted so lockout survives service restart.
- Generated runtime files such as `data/vault_metadata.json` and `data/users.json` are excluded from version control.
- Low-level Argon2, JSON, filesystem, base64, and cryptography errors are translated to stable public error codes.

---

## Validation

Automated tests cover:

- encrypted vault metadata contract
- no plaintext secret persistence
- repeat initialization rejection
- restart locked state
- correct and incorrect unlock behavior
- generic unlock failures
- KDF bounds validation
- locked KV/Transit gates
- registration success and failure cases
- secret-free account persistence
- login/session success and expiry
- restart invalidation of sessions
- five-failure account lockout
- CLI prompt-only behavior and stable outputs

The expected validation command is:

```bash
pytest
```

At the time of Feature 0.1 completion, the full suite passed with 45 tests. Feature 0.2 tasks are marked complete in `specs/002-user-auth/tasks.md` and add coverage for authentication repository, service, CLI, lockout, and protected-operation ordering.
