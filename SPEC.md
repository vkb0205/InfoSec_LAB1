# SPEC.md — Mini Vault

Source: `LAB1/Crypt_proj1.pdf` — Assignment 1, Computer Security Course

## 1. Product Overview

Mini Vault is a secure secret-management application inspired by HashiCorp Vault. It provides:

1. **Secure Storage / KV Engine**
   - Stores user secrets as encrypted data at rest.
   - Only the rightful owner can read, write, or delete their secrets.

2. **Transit Engine**
   - Provides encryption, decryption, signing, and verification as a service.
   - Application clients can use cryptographic keys without ever receiving raw key material.

The system must ensure that sensitive data and key material are never stored in plaintext on disk and are never returned through any API.

---

## 2. Recommended Technology Stack

- Language: Python
- CLI interface is sufficient; REST API using FastAPI or Flask is encouraged.
- Password hashing: `bcrypt` or `argon2-cffi`
- Master passphrase KDF: Argon2id or PBKDF2-HMAC-SHA256
- Symmetric encryption: AES-256-GCM
- Signing: RSA-2048 or Ed25519 using `cryptography`
- Random generation: `secrets` or `os.urandom`
- Storage: SQLite or JSON files
- Testing: `pytest` recommended

---

## 3. Recommended Project Structure

```text
StudentID1_StudentID2_StudentID3/
├── README.md
├── requirements.txt
├── .env.example
├── main.py
├── src/
│   ├── core/       # Master passphrase, init/unlock, DEK
│   ├── auth/       # Register/login, session token
│   ├── kv/         # Secure Storage / KV Engine
│   ├── transit/    # Encryption and Signing as a Service
│   └── storage/    # Disk persistence
├── tests/
├── data/
│   ├── samples/
│   └── logs/
└── docs/
    └── report/
```

Submission package must be named:

```text
StudentID1_StudentID2_StudentID3.zip
```

Report must be named:

```text
docs/report/Report_StudentID1_StudentID2_StudentID3.pdf
```

---

## 4. Core Security Requirements

- The vault must start in a locked state after every restart.
- The plaintext Data Encryption Key, user passwords, named AES keys, and private signing keys must never be written to disk.
- All Feature 1 and Feature 2 operations must require:
  1. Vault unlocked state
  2. Valid unexpired session token
  3. Ownership authorization
- AES-GCM or another AEAD mode must be used for confidentiality and integrity.
- Tampered ciphertext or authentication tags must be detected and rejected.
- Access denied events must be logged.

---

## 5. Feature 0 — Initialization, Unlock, Registration, and Login

### 5.1 Vault Initialization and Unlock

#### User Story

As the person deploying Mini Vault, I set a single Master Passphrase when starting the system for the first time and must re-enter it every time the system restarts to unlock the vault.

#### Functional Requirements

1. On first run, the system prompts for a strong Master Passphrase.
2. The system derives a key from the passphrase using Argon2id or PBKDF2-HMAC-SHA256.
3. A random salt must be generated and stored separately.
4. The system generates a random Data Encryption Key, called the DEK.
5. The DEK is encrypted using AES-256-GCM with the key derived from the Master Passphrase.
6. Only the encrypted DEK and KDF metadata are written to disk.
7. After every restart, the vault state must default to `locked`.
8. While locked, all KV and Transit operations must fail with `VAULT_LOCKED`.
9. Unlocking requires the correct Master Passphrase.
10. If the passphrase is correct, the DEK is decrypted into memory and the vault becomes `unlocked`.
11. If the passphrase is wrong, decryption fails and the system must return a generic error without leaking details.

#### Data Contract

```json
{
  "kdf": "argon2id",
  "kdf_salt_b64": "<salt>",
  "encrypted_dek_b64": "<encrypted DEK>",
  "status": "locked"
}
```

#### Error Cases

- Wrong Master Passphrase: return a generic unlock failure.
- Feature 1 or Feature 2 called while locked: return `VAULT_LOCKED`.

#### Acceptance Criteria

- Plaintext DEK is never written to disk.
- After restart, vault is always locked until correct Master Passphrase is entered.
- Wrong Master Passphrase never reveals whether KDF, tag, or key validation failed.

---

### 5.2 User Identity Authentication

#### User Story

As a user, I register and log in so the system can identify me before allowing access to secrets or keys.

#### Functional Requirements

1. Register requires:
   - Email
   - Passphrase
   - Confirm passphrase
2. The system must check passphrase strength.
3. Email must be unique.
4. User passphrases must be hashed using bcrypt or Argon2.
5. Plain SHA hashing is forbidden.
6. Login requires email and passphrase.
7. Successful login issues a session token.
8. Session tokens must expire, recommended after 30 minutes.
9. Every Feature 1 and Feature 2 operation must require a valid session token.
10. Five consecutive failed login attempts must temporarily lock the account for exactly 5 minutes.
11. Login during account lockout must fail even if the correct passphrase is supplied.

#### Data Contract

```json
{
  "email": "alice@example.com",
  "password_hash": "<bcrypt_or_argon2_hash>",
  "failed_attempts": 0,
  "locked_until": null
}
```

#### Error Cases

- Account does not exist at login.
- Wrong passphrase.
- Session token expired.
- Account locked after five failed attempts.

#### Acceptance Criteria

- No Feature 1 or Feature 2 endpoint may skip session validation.
- Five wrong passphrase attempts lock the account for exactly 5 minutes.
- Correct passphrase cannot bypass the 5-minute lockout.

---

## 6. Feature 1 — Secure Storage / KV Engine

### 6.1 Encrypted-at-Rest Storage

#### User Story

As a user, I want to store a secret under a path and retrieve the exact same content later without exposing plaintext in storage files.

#### Functional Requirements

1. `write(path, data, token)` stores any JSON object under a path.
2. The full JSON payload must be encrypted using AES-256-GCM with the current DEK.
3. A fresh random nonce must be generated for every write.
4. Nonces must never be reused with the same key.
5. The system stores only ciphertext, nonce, tag, and metadata on disk.
6. Existing paths are overwritten directly.
7. No version history is required.
8. `read(path, token)` decrypts the stored ciphertext using the DEK.
9. Authentication tag verification must happen before returning plaintext.
10. If tag verification fails, no data is returned.
11. `delete(path, token)` permanently deletes the record.

#### API Contract

| API | Input | Output |
|---|---|---|
| `write` | `path`, `data`, `token` | `created_at`, `updated_at` |
| `read` | `path`, `token` | decrypted data |
| `delete` | `path`, `token` | deletion confirmation |

#### Data Contract

```json
{
  "path": "secret/alice@example.com/db",
  "nonce_b64": "...",
  "ciphertext_b64": "...",
  "tag_b64": "..."
}
```

#### Error Cases

- Vault locked: `VAULT_LOCKED`
- Authentication tag mismatch: reject and return no secret
- Path not found: `NOT_FOUND`

#### Acceptance Criteria

- Write then read on the same path returns the original data exactly.
- Opening raw data files must show no plaintext secret fragments.
- Manually altering one byte in ciphertext or tag causes read to fail.

---

### 6.2 Ownership-Based Access Control

#### User Story

As a user, I am guaranteed that only I can read, write, or delete my own secrets.

#### Functional Requirements

1. Every secret path must use owner prefix:

   ```text
   secret/<email>/...
   ```

2. Every KV request must compare the email in the session token with the email in the path prefix.
3. If the token email does not match the path owner, the request must be denied before encryption or decryption occurs.
4. Access denial must not disclose whether the target path exists.
5. Denied access attempts must be logged with requester email and denied path.
6. Invalid or expired token must be rejected before authorization checks.

#### Error Cases

- Valid token but path belongs to another user: `PERMISSION_DENIED`
- Invalid or expired token: `UNAUTHENTICATED`

#### Acceptance Criteria

- User A reading `secret/<user-b-email>/...` must always be denied.
- Missing or invalid token must never reach the path ownership check.

---

## 7. Feature 2 — Transit Engine

### 7.1 Named Key Management

#### User Story

As a user, I want to create named encryption keys without having to generate or safeguard the raw AES key myself.

#### Functional Requirements

1. `create_key(key_name, token)` generates a random AES-256 key.
2. The key is bound to:
   - `key_name`
   - owner email from the token
   - `key_usage = "ENCRYPT_DECRYPT"`
3. The AES key must be encrypted with the DEK before storage.
4. The raw AES key must never be returned by any API.
5. `list_keys(token)` returns only key names and key usage for the current user.
6. `revoke_key(key_name, token)` permanently deletes a named key.
7. Duplicate key names for the same user must either be rejected or require overwrite confirmation; the chosen behavior must be documented.

#### Data Contract

```json
{
  "key_name": "my-key",
  "owner_email": "alice@example.com",
  "key_usage": "ENCRYPT_DECRYPT",
  "encrypted_key_material_b64": "<AES key encrypted with the DEK>"
}
```

#### Error Cases

- Duplicate key name for the same user.
- Creating or deleting while vault is locked: `VAULT_LOCKED`

#### Acceptance Criteria

- No API, including `list_keys`, returns real AES key material.

---

### 7.2 Encryption and Decryption as a Service

#### User Story

As a user, I send data to Mini Vault to be encrypted with my named key and later send the ciphertext back for decryption without knowing the raw key.

#### Functional Requirements

1. `encrypt(key_name, plaintext_b64, token)` verifies ownership of `key_name`.
2. The system temporarily decrypts the AES key using the in-memory DEK.
3. The plaintext is encrypted with AES-256-GCM using a fresh random nonce.
4. The returned ciphertext must be self-describing and include the key name.
5. Ciphertext format:

   ```text
   vault:<key_name>:<base64(nonce+ct+tag)>
   ```

6. `decrypt(ciphertext, token)` parses the key name from the ciphertext.
7. The system checks permission for that key.
8. The system decrypts the corresponding AES key using the DEK.
9. The system decrypts and verifies the AES-GCM tag.
10. On success, plaintext is returned as base64.

#### API Contract

| API | Input | Output |
|---|---|---|
| `encrypt` | `key_name`, `plaintext_b64`, `token` | `vault:<key_name>:<base64(nonce+ct+tag)>` |
| `decrypt` | `ciphertext`, `token` | `plaintext_b64` |

#### Error Cases

- Malformed or truncated ciphertext.
- GCM tag mismatch.
- Key does not exist or was revoked.
- Key usage is `SIGN_VERIFY` instead of `ENCRYPT_DECRYPT`; reject with an invalid key usage error.

#### Acceptance Criteria

- Encrypt followed by decrypt returns the exact original plaintext.
- Must work for text, JSON, and binary base64 payloads.
- Altering any single byte in ciphertext causes decrypt to fail.
- Encrypt, decrypt, and list keys never return the raw AES key.

---

### 7.3 Named-Key Access Control

#### User Story

As a user, I am guaranteed that only I can use my own named key for encryption and decryption.

#### Functional Requirements

1. Every named key must store `owner_email`.
2. Every encrypt/decrypt request must compare token email with key owner email.
3. If the caller is not the key owner, the request must be denied before any cryptographic operation.
4. Error messages must not disclose whether the key exists.
5. Denied access attempts must be logged with requester email and denied key name.

#### Error Cases

- Valid token but not key owner: `PERMISSION_DENIED`

#### Acceptance Criteria

- User A attempting to encrypt/decrypt using User B's key must always be denied.

---

### 7.4 Sign and Verify as a Service

#### User Story

As a user, I want to digitally sign a message with my own signing key and verify signatures without ever handling the private key.

#### Functional Requirements

1. `create_signing_key(key_name, signing_algorithm, token)` generates an asymmetric key pair.
2. Supported algorithms may include:
   - Ed25519
   - RSA-2048 with RSASSA_PKCS1_V1_5_SHA_256
3. The key is bound to:
   - `key_name`
   - owner email
   - `key_usage = "SIGN_VERIFY"`
   - signing algorithm
4. The private key must be encrypted with the DEK before storage.
5. The public key is stored for verification.
6. The private signing key must never be returned by any API.
7. `sign(key_name, message_b64, message_type, token)` signs a message using the private key.
8. `message_type` must be either:
   - `RAW`: system hashes the message with SHA-256 first, if required by the algorithm
   - `DIGEST`: client sends a precomputed digest
9. For `DIGEST`, digest length must match the expected hash output size.
10. `verify(key_name, message_b64, message_type, signature_b64, token)` verifies the signature.
11. Verification returns a structured result instead of silently assuming success.
12. Only the owner may call `sign`.
13. Required scope also allows only the owner to call `verify`.

#### API Contract

| API | Input | Output |
|---|---|---|
| `create_signing_key` | `key_name`, `signing_algorithm`, `token` | confirmation |
| `sign` | `key_name`, `message_b64`, `message_type`, `token` | `signature_b64`, `key_name`, `signing_algorithm` |
| `verify` | `key_name`, `message_b64`, `message_type`, `signature_b64`, `token` | `key_name`, `signature_valid`, `signing_algorithm` |

#### Data Contract

```json
{
  "key_name": "my-signing-key",
  "owner_email": "alice@example.com",
  "key_usage": "SIGN_VERIFY",
  "signing_algorithm": "ED25519",
  "encrypted_private_key_b64": "<private key encrypted with the DEK>",
  "public_key_b64": "<public key used internally by the server to verify>"
}
```

#### Error Cases

- `message_type = DIGEST` but digest length is invalid.
- Verify called with a signing algorithm that does not match the key.
- Key does not exist or was revoked.
- Key usage is `ENCRYPT_DECRYPT` instead of `SIGN_VERIFY`; reject with invalid key usage.
- Malformed or wrong-length signature passed to verify must return `signature_valid: false` or a clear rejection without unhandled exceptions.

#### Acceptance Criteria

- Sign followed by verify on the unmodified message returns `signature_valid: true`.
- Altering one byte of the message returns `signature_valid: false`.
- A signature produced by one key must fail verification against another key.
- No API returns the raw private signing key.

---

## 8. Required Tests

At minimum, implement tests for the following cases:

1. Vault initialization stores only encrypted DEK.
2. Vault restarts in locked state.
3. Wrong Master Passphrase fails unlock.
4. Feature 1 and Feature 2 fail while locked with `VAULT_LOCKED`.
5. User registration stores bcrypt or Argon2 password hash only.
6. Successful login returns session token.
7. Expired session token is rejected.
8. Five consecutive failed logins lock the account for 5 minutes.
9. KV write/read round trip returns original JSON exactly.
10. KV data file contains no plaintext secret fragments.
11. Tampered KV ciphertext or tag is rejected.
12. User A cannot access User B's KV path.
13. Invalid token is rejected before path authorization.
14. Named AES key creation stores only encrypted key material.
15. `list_keys` never returns raw key material.
16. Transit encrypt/decrypt round trip succeeds for text, JSON, and binary base64.
17. Tampered transit ciphertext fails decryption.
18. User A cannot use User B's named key.
19. Encrypt/decrypt rejects keys with `SIGN_VERIFY` usage.
20. Signing key creation stores encrypted private key only.
21. Sign then verify on original message succeeds.
22. Verify on tampered message fails.
23. Cross-key signature verification fails.
24. Sign/verify rejects keys with `ENCRYPT_DECRYPT` usage.

---

## 9. Optional Extra Credit Features

Only attempt these after all required features are stable.

| Feature | Extra Credit |
|---|---:|
| Sharing named keys/secrets across multiple users through full Policy/ACL system | +0.4 |
| MFA using OTP/TOTP during login | +0.2 |
| Shamir's Secret Sharing for vault unlock | +0.5 |
| Transit key rotation with key versions | +0.4 |
| KV versioning with overwrite history | +0.3 |
| Tamper-evident hash-chained audit log | +0.3 |
| Allow `verify()` for non-owner authenticated users with explicit share/grant policy | +0.3 |

Total extra credit is capped at 1.0 point.

---

## 10. Deliverables

Submission must include:

1. Full source code organized into modules.
2. `README.md` with run instructions.
3. `requirements.txt`.
4. Report PDF under `docs/report/`.
5. Team name, student IDs, and task assignment in the report.
6. Architecture diagram.
7. Technical explanation for:
   - 0.1 Init and unlock
   - 0.2 User authentication
   - 1.1 KV encrypted storage
   - 1.2 KV access control
   - 2.1 Transit key management
   - 2.2 Transit encrypt/decrypt
   - 2.3 Transit access control
   - 2.4 Sign and verify
8. Screenshots of the demo.
9. Optional features completed, if any.
10. Test data files:
    - encrypted KV data file
    - sample Transit ciphertext
11. Demo video is recommended, 3–5 minutes.

Demo should show:

- Vault unlock
- Write/read a secret
- Denied cross-user secret access
- Create a named key
- Encrypt/decrypt with Transit
- Denied cross-user key usage
- Sign a message
- Verify valid signature
- Verify tampered message as invalid

---

## 11. Grading Rubric

| No. | Category | Criteria | Points |
|---:|---|---|---:|
| 1 | 0.1 Init and Unlock | Correct KDF, locked after restart, no plaintext DEK leak | 1.0 |
| 2 | 0.2 User Authentication | Correct password hashing, session token, 5-attempt lockout | 1.0 |
| 3 | 1.1 KV Encrypted-at-Rest | Correct AEAD, detects tampering, no plaintext leak | 1.25 |
| 4 | 1.2 KV Access Control | Blocks unauthorized cross-user access | 1.0 |
| 5 | 2.1 Transit Key Management | Named key never returned in plaintext | 1.0 |
| 6 | 2.2 Transit Encrypt/Decrypt | Correct round trip, detects tampered ciphertext | 1.25 |
| 7 | 2.3 Transit Access Control | Blocks use of another user's key | 1.0 |
| 8 | 2.4 Sign and Verify | Correct sign/verify, rejects tampered messages and cross-key signatures | 1.0 |
| 9 | Report, README, Task Assignment | Clear, complete, illustrated, with run instructions | 0.75 |
| 10 | Product Demo | Clear demo including denied access and sign/verify cases | 0.75 |

Total: 10 points
