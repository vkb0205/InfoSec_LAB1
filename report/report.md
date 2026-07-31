# Mini Vault — Project Report

## 1. Project Information

### 1.1 Team

| Field | Value |
|---|---|
| Team name | *[Replace before submission]* |
| Student 1 — name / ID | *[Replace before submission]* |
| Student 2 — name / ID | *[Replace before submission]* |
| Student 3 — name / ID | *[Replace before submission]* |

### 1.2 Task Assignment

| Member | Primary responsibility | Delivered work |
|---|---|---|
| Member 1 | Vault core and authentication | Vault initialization/unlock, DEK protection, user registration/login, session handling, REST and CLI integration |
| Member 2 | KV secure storage | AES-GCM secret storage, ownership-based path ACL, access-denied logging, KV CLI/REST integration |
| Member 3 | Transit, testing, report, demo | Named-key Transit service, encrypt/decrypt, Ed25519 signing, optional features, tests, report and demo |

> Replace member labels with names and IDs before exporting the final PDF.

### 1.3 Scope

Mini Vault is a local secret-management application inspired by HashiCorp Vault. It implements:

- **0.1** Vault initialization and unlock.
- **0.2** User registration, login, session expiry, and account lockout.
- **1.1** Encrypted KV storage.
- **1.2** Ownership-based KV access control.
- **2.1** Named Transit key management.
- **2.2** Transit encryption and decryption.
- **2.3** Named-key ownership control.
- **2.4** Ed25519 signing and verification.
- **Optional:** KV versioning and Transit key rotation.

Not claimed: Shamir unlock, MFA/TOTP, policy-based sharing, hash-chained audit logs, RSA signing, Transit REST endpoints, or a Transit `message_type` DIGEST API.

---

## 2. Architecture

### 2.1 Architecture Diagram

```text
                           Client Layer
              +-----------------------------------+
              | CLI / interactive menu            |
              | REST client: curl, browser, etc.  |
              +----------------+------------------+
                               |
              +----------------v------------------+
              | Application Layer                 |
              | argparse CLI | FastAPI server      |
              +----------------+------------------+
                               |
       +-----------------------+------------------------+
       |                       |                        |
+------v-------+        +------v-------+        +-------v--------+
| Vault 0.1    |        | Auth 0.2     |        | KV 1.1 / 1.2   |
| init/unlock  |        | users/tokens |        | encrypted CRUD |
| in-RAM DEK   |        | lockout      |        | path ACL       |
+------+-------+        +------+-------+        +-------+--------+
       |                       |                        |
       |                       |                +-------v--------+
       |                       |                | Transit 2.1–2.4|
       |                       |                | keys / crypto  |
       |                       |                +----------------+
       |                       |                        |
+------v-----------------------v------------------------v--------+
| Persistent Storage                                            |
| vault_metadata.json | users.json | kv_store.json              |
| transit_keys.json   | access_denied.log                        |
+----------------------------------------------------------------+
```

### 2.2 Design Summary

Vault and Auth provide the trust boundary for both engines:

```text
unlock vault -> validate session -> authorize owner -> perform crypto operation
```

- **Vault:** keeps the plaintext Data Encryption Key (DEK) only in process memory after successful unlock.
- **Auth:** maps a valid, unexpired session token to a canonical user email.
- **KV:** encrypts user secrets directly with the DEK; each path belongs to one email.
- **Transit:** stores DEK-wrapped named AES or Ed25519 key material; server performs encryption, decryption, signing, and verification without returning private key material.

CLI supports all implemented features. REST supports Vault, Auth, and KV. Transit is exposed through CLI and interactive mode only.

### 2.3 Runtime and Persistence Model

| Item | Stored location | Persists after restart? | Plaintext secret stored? |
|---|---|---:|---:|
| Master passphrase | Nowhere | No | No |
| DEK | RAM after unlock; wrapped metadata on disk | RAM: No | No |
| User passphrase | Nowhere; Argon2 hash stored | Hash: Yes | No |
| Session token | `AuthService._sessions` RAM map | No | No |
| KV secret | `data/kv_store.json` | Yes | No |
| Transit AES/private key | `data/transit_keys.json`, DEK-wrapped | Yes | No |

A new process has no DEK and no sessions. Therefore every restart starts with a locked vault and invalidates all prior tokens.

---

## 3. Feature 0 — Vault Foundation and Authentication

### 3.1 Feature 0.1 — Vault Initialization and Unlock

#### Purpose

Feature 0.1 protects one random 32-byte **Data Encryption Key (DEK)**. Later KV and Transit operations require this key. The DEK is never saved in plaintext.

#### Initialization

1. User enters a strong Master Passphrase through `getpass` or a REST JSON body.
2. Passphrase policy requires at least 12 characters with lowercase, uppercase, digit, and symbol.
3. System generates random values:
   - 16-byte Argon2id salt;
   - 32-byte DEK;
   - 12-byte AES-GCM nonce.
4. Argon2id derives a 32-byte Key Encryption Key (KEK) from the Master Passphrase.
5. AES-256-GCM encrypts the DEK under the KEK with fixed authenticated data `b"mini-vault:vault-metadata:v1"`.
6. Only metadata and the encrypted DEK envelope are atomically written to disk.
7. DEK and KEK references are discarded. Vault remains locked after initialization.

```text
Master Passphrase + salt + Argon2id parameters
                    |
                    v
              KEK, 32 bytes
                    |
                    v
AES-256-GCM(KEK, nonce, DEK, AAD)
                    |
                    v
ciphertext || tag saved in vault_metadata.json
```

Configured Argon2id parameters: memory cost 65536 KiB, time cost 3, parallelism 1, and hash length 32 bytes. Salt and KDF parameters are public metadata; passphrase, KEK, and plaintext DEK are never persisted.

#### Unlock and State

On unlock, Mini Vault reads and validates metadata, re-derives the KEK using stored Argon2id parameters, then asks AES-GCM to decrypt and authenticate the DEK envelope. A valid tag produces the DEK in RAM. Any wrong passphrase, malformed metadata, or authentication failure returns the same public error: `UNLOCK_FAILED`.

| State | Condition |
|---|---|
| `uninitialized` | Metadata file does not exist |
| `locked` | Metadata exists but `_dek is None` |
| `unlocked` | Plaintext DEK exists only in current process memory |

After restart, `_dek` is absent, so state is always `locked`. Calling protected KV or Transit code while locked returns `VAULT_LOCKED`.

#### Metadata Contract

`data/vault_metadata.json` stores only KDF configuration and a GCM envelope:

```json
{
  "schema_version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "salt_b64": "...",
    "memory_cost_kib": 65536,
    "time_cost": 3,
    "parallelism": 1,
    "hash_len": 32
  },
  "aead": {
    "algorithm": "aes-256-gcm",
    "nonce_b64": "...",
    "ciphertext_and_tag_b64": "..."
  }
}
```

| Security property | Implementation |
|---|---|
| Password resistance | Argon2id is memory-hard; salt prevents precomputed attacks |
| DEK confidentiality | AES-256-GCM encrypts DEK under a passphrase-derived KEK |
| Metadata integrity | GCM tag authenticates ciphertext, nonce, and fixed AAD |
| Restart safety | Unlock state is not written to disk |
| Failure privacy | Wrong password and corrupted metadata both return `UNLOCK_FAILED` |

#### Interfaces and Errors

| Interface | Operations |
|---|---|
| CLI | `status`, `init`, `unlock` |
| REST | `GET /v1/status`, `POST /v1/init`, `POST /v1/unlock` |

| Condition | Public code |
|---|---|
| Weak passphrase or invalid input | `INVALID_INPUT` |
| Metadata already exists | `ALREADY_INITIALIZED` |
| Wrong passphrase, tampered, or invalid metadata | `UNLOCK_FAILED` |
| Protected operation before unlock | `VAULT_LOCKED` |

Implementation: `src/core/vault.py`, `src/crypto_utils.py`, `src/storage/repository.py`, `src/api/app.py`, and `main.py`.

---

### 3.2 Feature 0.2 — User Authentication

#### Purpose

Feature 0.2 establishes caller identity before KV or Transit access. Authentication is independent of vault unlock: users may register or log in while the vault is locked, but protected crypto operations require both unlock and a valid session.

#### Registration

1. Email is stripped, case-folded, and validated.
2. Passphrase confirmation must match.
3. Same strong-passphrase policy used by vault initialization is enforced.
4. `argon2.PasswordHasher` hashes the user passphrase.
5. Repository creates the account; duplicate emails return `DUPLICATE_USER`.

`data/users.json` stores canonical email, Argon2 hash, consecutive failed-login count, and lockout expiry. It never stores plaintext passphrases or session tokens.

#### Login, Sessions, and Lockout

```text
login(email, passphrase)
  -> reject active lockout
  -> verify stored Argon2 hash
  -> failure: increment counter
  -> fifth consecutive failure: lock account for 5 minutes
  -> success: reset counter and create opaque token
  -> token -> (email, expiry) stored only in RAM
```

- Tokens use `secrets.token_urlsafe(32)`.
- Session lifetime: 30 minutes.
- Five consecutive failures create an exact five-minute lockout.
- Successful login resets failure count and lockout state.
- Expired, unknown, missing, or post-restart tokens return `UNAUTHENTICATED`.
- Account lockout survives restart because `locked_until` is persisted; sessions do not.

#### Protected Operation Order

All protected calls follow this boundary order:

```text
1. Vault unlocked?          no -> VAULT_LOCKED
2. Session token valid?     no -> UNAUTHENTICATED
3. Caller owns target?      no -> deny before crypto
4. Perform requested operation
```

This order avoids cryptographic work with an unavailable DEK, rejects invalid identities before authorization, and prevents unauthorized decryption.

| Interface | Operations |
|---|---|
| CLI | `register`, `login` |
| REST | `POST /v1/auth/register`, `POST /v1/auth/login`, `GET /v1/auth/session` |

| Condition | Public code |
|---|---|
| Invalid email, mismatch, weak passphrase | `INVALID_INPUT` |
| Existing email | `DUPLICATE_USER` |
| Invalid passphrase | `INVALID_CREDENTIALS` |
| Five-failure lockout active | `ACCOUNT_LOCKED` |
| Missing, invalid, or expired token | `UNAUTHENTICATED` |

Implementation: `src/auth/service.py`, `src/storage/repository.py`, `src/api/app.py`, and `main.py`.

---

## 4. Feature 1 — KV Secure Storage

### 4.1 Feature 1.1 — Encrypted-at-Rest Storage

#### Purpose

Feature 1.1 stores user secrets without exposing their plaintext in the filesystem. KV uses the unlocked vault DEK directly as its AES-256-GCM key.

#### Write, Read, and Delete

**Write**

1. Check vault, session, and ownership gates.
2. Encode secret text as UTF-8 bytes.
3. Generate a fresh random 12-byte nonce.
4. Encrypt with AES-256-GCM using current DEK.
5. Split GCM output into ciphertext and 16-byte authentication tag.
6. Base64-encode nonce, ciphertext, and tag for JSON persistence.

```text
plaintext UTF-8 + DEK + fresh nonce
              |
              v
          AES-256-GCM
              |
              v
nonce_b64 + ciphertext_b64 + tag_b64 in kv_store.json
```

**Read** loads the envelope, Base64-decodes it, and calls AES-GCM decrypt. AES-GCM verifies the authentication tag before returning plaintext. Any changed nonce, ciphertext, or tag fails closed; no plaintext is returned.

**Delete** removes the complete path record and its version history without decrypting it.

#### Stored Data

`data/kv_store.json` contains path metadata plus encrypted envelopes. It does not contain the DEK or plaintext secret data.

```json
{
  "path": "secret/alice@example.com/database",
  "latest_version": 2,
  "history": [
    {
      "version": 2,
      "nonce_b64": "...",
      "ciphertext_b64": "...",
      "tag_b64": "...",
      "created_at": 0
    }
  ]
}
```

Path text remains visible because it is used for ownership routing. Secret value remains confidential without the in-memory DEK.

#### Security Decisions

| Risk | Control |
|---|---|
| Disk disclosure | AES-256-GCM ciphertext only; DEK absent from KV file |
| GCM nonce reuse | New random 12-byte nonce on every write |
| Ciphertext tampering | GCM tag verification before plaintext return |
| Vault restart | DEK disappears; ciphertext remains unreadable until unlock |
| Accidental overwrite loss | Optional version history preserves prior encrypted versions |

KV routes: `POST /v1/kv/write`, `GET /v1/kv/read`, and `DELETE /v1/kv/delete`. CLI and interactive mode use the same KV engine.

Implementation: `src/kv/crypto_utils.py`, `src/kv/kv_engine.py`, `src/kv/storage.py`, `src/api/app.py`, and `main.py`.

---

### 4.2 Feature 1.2 — Ownership-Based Access Control

#### Purpose

Encryption protects disk contents, but server-side authorization prevents one authenticated user from asking the vault to decrypt another user's data. Every KV path identifies its owner:

```text
secret/<owner-email>/<resource...>
```

Examples:

| Path | Valid | Owner |
|---|---:|---|
| `secret/alice@example.com/db` | Yes | `alice@example.com` |
| `secret/bob@example.com/app/api` | Yes | `bob@example.com` |
| `notes/alice@example.com/x` | No | — |
| `secret/alice@example.com` | No | — |

#### Authorization Flow

1. Vault gate obtains DEK; locked vault returns `VAULT_LOCKED`.
2. KV engine validates path structure.
3. Auth service validates session token and returns caller email.
4. Engine compares caller email with path owner.
5. Mismatch writes an audit entry and returns `PERMISSION_DENIED`.
6. Only a matching owner reaches encryption, decryption, or deletion.

```text
Bob token + secret/alice@example.com/payroll
  -> caller != owner
  -> access_denied.log
  -> PERMISSION_DENIED
  -> no record lookup or decryption
```

Because ownership is checked before storage lookup, a foreign user receives `PERMISSION_DENIED` whether Alice's path exists or not. This prevents an existence oracle.

Denied attempts are recorded in `data/logs/access_denied.log` with operation, requested path, caller, and path owner. Owner access to a missing record returns `NOT_FOUND`.

| Condition | Result |
|---|---|
| Invalid path format | `INVALID_INPUT` |
| Missing, unknown, or expired token | `UNAUTHENTICATED` |
| Valid token for another owner | `PERMISSION_DENIED`, logged |
| Owner requests missing path | `NOT_FOUND` |
| Locked vault | `VAULT_LOCKED` |

Implementation: `src/kv/kv_engine.py`, `src/auth/service.py`, `src/api/app.py`, and `data/logs/access_denied.log`.

---

## 5. Feature 2 — Transit Engine

### 5.1 Feature 2.1 — Named Key Management

#### Purpose

Transit provides cryptography as a service. Users refer to keys by name; they never receive raw AES keys or Ed25519 private keys.

#### Encryption Keys

`create_key(token, key_name)`:

1. Requires unlocked vault and valid session.
2. Generates random 32-byte AES-256 key material.
3. Binds key name and owner email to a key record.
4. Encrypts key material with AES-GCM under the vault DEK.
5. Stores Base64-wrapped material in `data/transit_keys.json`.
6. Returns metadata only: key name, usage, and current version.

Encryption keys use `key_usage = "ENCRYPT_DECRYPT"` and `algorithm = "AES-256-GCM"`. Key names are globally unique in the local store. Duplicate names are rejected as `INVALID_INPUT`.

The service also implements:

- `list_keys(token)`: returns only caller-owned key metadata; never material.
- `revoke_key(token, key_name)`: permanently removes a caller-owned key.

#### Key Record

```json
{
  "name": "payments-key",
  "owner_email": "alice@example.com",
  "key_usage": "ENCRYPT_DECRYPT",
  "algorithm": "AES-256-GCM",
  "encrypted_key_material_b64": "...",
  "latest_version": 1,
  "versions": { "1": { "encrypted_key_material_b64": "..." } }
}
```

The on-disk record contains wrapped material, ownership metadata, timestamps, and version information. It never contains plaintext AES keys or Ed25519 private keys.

Implementation: `src/transit/service.py` and `src/storage/repository.py`.

---

### 5.2 Feature 2.2 — Encryption and Decryption as a Service

#### Encrypt

`encrypt(token, key_name, plaintext_b64)` validates unlock, session, ownership, and key usage. It unwraps the current AES key in RAM, Base64-decodes input, then encrypts it using AES-256-GCM and a fresh 12-byte nonce.

Returned ciphertext is self-describing:

```text
vault:<key_name>:<version>:<base64(nonce || ciphertext || tag)>
```

The format identifies key and version needed for later decryption without exposing key material.

#### Decrypt

`decrypt(token, ciphertext)` parses the `vault:` format, validates caller ownership and key usage, unwraps the matching key version in RAM, then uses AES-GCM decrypt. Authentication failure or malformed ciphertext produces no plaintext.

| Control | Result |
|---|---|
| Fresh nonce on encryption | Prevents reuse of a GCM nonce under the same key |
| Version in ciphertext | Supports decryption after key rotation |
| GCM tag verification | Detects altered nonce, ciphertext, or tag |
| Server-side key handling | Client receives ciphertext or plaintext only, never raw AES key |
| Usage check | Signing keys cannot be used for encrypt/decrypt |

Interactive mode accepts UTF-8 text, Base64-encodes it before service call, and displays returned ciphertext or Base64 plaintext. Core service accepts Base64 so arbitrary binary data is supported.

Implementation: `src/transit/service.py`.

---

### 5.3 Feature 2.3 — Named-Key Access Control

Every Transit key record includes `owner_email`. Every key operation validates the session first, then checks record ownership before unwrapping key material.

```text
1. Vault unlocked?            no -> VAULT_LOCKED
2. Session valid?             no -> UNAUTHENTICATED
3. Requested key owned?       no -> fail closed
4. Key usage valid?           no -> INVALID_INPUT
5. Unwrap material in RAM and perform crypto
```

Covered operations: create, list, revoke, rotate, encrypt, decrypt, sign, and verify.

Current implementation deliberately uses `INVALID_INPUT` for both a missing key and a foreign-owned key. This gives a shared failure response and avoids revealing whether a foreign key name exists. It still rejects foreign key use before DEK unwrap or cryptographic processing. KV access-denied logging is implemented; equivalent Transit denial logging is not claimed.

| Property | Implementation |
|---|---|
| Owner identity | Canonical email from validated session token |
| Key isolation | `owner_email` comparison before unwrap |
| Existence protection | Same `INVALID_INPUT` branch for missing/foreign key |
| Private material exposure | Never returned in API, CLI, or storage plaintext |

Implementation: `src/transit/service.py`.

---

### 5.4 Feature 2.4 — Signing and Verification

#### Signing Keys

`create_signing_key(token, key_name)` creates an Ed25519 key pair:

- Private key is serialized and AES-GCM-wrapped under the vault DEK.
- Public key is stored as Base64 because it is non-secret.
- Record uses `key_usage = "SIGN_VERIFY"` and `algorithm = "ED25519"`.
- Creation returns metadata only; never the private key.

#### Sign and Verify

`sign(token, key_name, message_b64)` validates unlock, session, owner, and usage. It unwraps the current private key in RAM, signs decoded message bytes, and returns `signature_b64`.

`verify(token, key_name, message_b64, signature)` checks the matching owner key and returns structured validity rather than raising an unhandled error for a bad signature:

```json
{
  "key_name": "release-signing-key",
  "signature_valid": true,
  "signing_algorithm": "ED25519"
}
```

Changing either message or signature makes `signature_valid` false. Encryption keys cannot sign, and signing keys cannot encrypt.

Implementation: `src/transit/service.py`.

---

## 6. Optional Features Completed

### 6.1 KV Versioning (+0.3)

KV writes append an encrypted version to `history` and increment `latest_version`.

- Default read returns latest version.
- `read(path, token, version=N)` returns a selected historical version for its owner.
- Missing version returns `VERSION_NOT_FOUND`.
- Delete removes complete history.
- REST supports `GET /v1/kv/read?path=...&version=N`.

Each version keeps an independent AES-GCM envelope. Historical plaintext is never stored.

### 6.2 Transit Key Rotation (+0.4)

`rotate_key(token, key_name)` creates fresh AES-256 or Ed25519 key material and increments `latest_version` while retaining previous DEK-wrapped versions.

- New encryption uses newest version.
- Ciphertext embeds key version.
- Old ciphertext remains decryptable using retained old material.
- New signatures use latest private key.
- Verification checks retained public-key versions, so old valid signatures remain valid.
- Raw key material remains wrapped at rest and absent from responses.

Automated coverage includes `tests/test_kv.py`, `tests/test_api_kv_1.py`, and `tests/test_transit_bonus.py`.

---

## 7. Demonstration Evidence

> Replace each placeholder below with the stated screenshot before final submission. Do not show real personal secrets, production tokens, or private passphrases.

### 7.1 Required Screenshots

**Figure 1 — Vault initialization and unlock**

> **[SCREENSHOT PLACEHOLDER]** Show `init`, successful `unlock`, then `status: unlocked`. Include no visible Master Passphrase.

**Figure 2 — Registration, login, and session**

> **[SCREENSHOT PLACEHOLDER]** Show successful user registration/login and token-based session validation. Mask token except a short prefix/suffix.

**Figure 3 — KV write and read**

> **[SCREENSHOT PLACEHOLDER]** Show authenticated owner writing `secret/<email>/demo`, then reading same plaintext.

**Figure 4 — KV encrypted-at-rest evidence**

> **[SCREENSHOT PLACEHOLDER]** Show `data/kv_store.json`; confirm written secret text is absent and only Base64 envelopes are visible.

**Figure 5 — KV cross-user denial**

> **[SCREENSHOT PLACEHOLDER]** Show Bob using a valid token against Alice path and receiving `PERMISSION_DENIED`.

**Figure 6 — KV denial audit evidence**

> **[SCREENSHOT PLACEHOLDER]** Show matching entry in `data/logs/access_denied.log` with operation, caller, owner, and path.

**Figure 7 — Transit encryption and decryption**

> **[SCREENSHOT PLACEHOLDER]** Show named key creation, `vault:<key>:<version>:...` ciphertext, and successful round trip.

**Figure 8 — Transit key protection**

> **[SCREENSHOT PLACEHOLDER]** Show `data/transit_keys.json` containing wrapped key material, not raw AES or private key bytes.

**Figure 9 — Transit cross-user denial**

> **[SCREENSHOT PLACEHOLDER]** Show second user attempting to use foreign named key; show fail-closed response and no plaintext output.

**Figure 10 — Sign and verify**

> **[SCREENSHOT PLACEHOLDER]** Show valid Ed25519 signature verification, then false result after changing message or signature.

### 7.2 Optional-Feature Screenshots

**Figure 11 — KV versioning**

> **[SCREENSHOT PLACEHOLDER]** Show two writes to same path, latest read, and successful historical read using `version`.

**Figure 12 — Transit key rotation**

> **[SCREENSHOT PLACEHOLDER]** Show rotation increasing version and successful decryption of ciphertext produced before rotation.

### 7.3 Test Execution

```bash
pytest
```

Relevant test groups:

| Area | Test files |
|---|---|
| Vault initialization and unlock | `tests/test_vault_initialization.py`, `tests/test_vault_unlock.py` |
| Authentication and sessions | `tests/test_auth_service.py`, `tests/test_api_auth_0_2.py` |
| KV encryption and ACL | `tests/test_kv.py`, `tests/test_api_kv_1.py` |
| Locked/authentication gates | `tests/test_locked_kv_gate.py`, `tests/test_auth_kv_gate.py`, `tests/test_locked_transit_gate.py`, `tests/test_auth_transit_gate.py` |
| Transit CLI and optional features | `tests/test_cli_encrypt_flow.py`, `tests/test_transit_bonus.py` |

---

## 8. Conclusion

Mini Vault implements a layered security model:

```text
Master Passphrase protects DEK
DEK protects KV secrets and Transit private material
Session token identifies caller
Owner check restricts path or key use
AES-GCM and Ed25519 protect application data
```

Feature 0.1 keeps DEK plaintext only in RAM after authenticated unlock. Feature 0.2 supplies Argon2-protected accounts, expiring sessions, and persistent lockout. Feature 1 stores secrets with AES-256-GCM and prevents cross-user path access. Feature 2 provides named AES encryption and Ed25519 signatures without exposing raw key material. Optional KV versioning and Transit rotation retain encrypted history and key-version compatibility.

No Master Passphrase, plaintext DEK, user passphrase, session token, KV secret, raw Transit AES key, or Transit private key is intentionally persisted in plaintext.
