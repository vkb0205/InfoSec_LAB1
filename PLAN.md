# PLAN.md — 7-Day Task Plan for Mini Vault

This plan divides the Mini Vault project into clear responsibilities for **3 people over 7 days**, based on the requirements in `SPEC.md`.

---

## 1. Team Roles

| Member | Main Responsibility |
|---|---|
| Person 1 | Core vault system, authentication, session management |
| Person 2 | KV secure storage and access control |
| Person 3 | Transit engine, signing/verification, documentation/demo |

---

## 2. High-Level Feature Ownership

### Person 1 — Core and Authentication

Responsible for:

- Project structure
- Vault initialization
- Master passphrase KDF
- DEK generation and encryption
- Locked/unlocked vault state
- User registration
- Password hashing
- Login and session token handling
- Session expiry
- Failed-login lockout
- README setup instructions

### Person 2 — KV Engine

Responsible for:

- Encrypted KV storage
- AES-256-GCM encryption at rest
- Fresh nonce generation per write
- KV `write`, `read`, and `delete`
- KV ownership authorization
- Access-denied logging for KV operations
- KV tampering tests
- KV demo evidence

### Person 3 — Transit Engine and Report

Responsible for:

- Named AES key creation, listing, and revocation
- Transit encryption/decryption service
- Transit access control
- Signing key creation
- Sign/verify service
- Transit tampering tests
- Architecture diagram
- Final report PDF
- Demo video

---

## 3. Daily Plan

## Day 1 — Project Setup and Architecture

### Goals

- Create the base project structure.
- Agree on architecture and storage format.
- Define interfaces between modules.

### Person 1 Tasks

- Create project structure:

```text
src/core/
src/auth/
src/kv/
src/transit/
src/storage/
tests/
docs/report/
data/
```

- Create initial files:
  - `README.md`
  - `requirements.txt`
  - `.env.example`
  - `main.py`
- Decide storage format: SQLite or JSON files.
- Implement basic CLI or REST skeleton.
- Define shared error codes:
  - `VAULT_LOCKED`
  - `UNAUTHENTICATED`
  - `PERMISSION_DENIED`
  - `NOT_FOUND`
  - `INVALID_KEY_USAGE`

### Person 2 Tasks

- Design KV storage data format.
- Define secret path rule:

```text
secret/<email>/...
```

- Prepare KV module interfaces:

```python
write(path, data, token)
read(path, token)
delete(path, token)
```

### Person 3 Tasks

- Design Transit module interfaces:

```python
create_key(key_name, token)
list_keys(token)
revoke_key(key_name, token)
encrypt(key_name, plaintext_b64, token)
decrypt(ciphertext, token)
create_signing_key(key_name, signing_algorithm, token)
sign(key_name, message_b64, message_type, token)
verify(key_name, message_b64, message_type, signature_b64, token)
```

- Start report outline.
- Prepare initial architecture diagram draft.

### Day 1 Deliverables

- Project skeleton exists.
- Interfaces are agreed between all members.
- Storage format is chosen.
- Report outline is started.

---

## Day 2 — Feature 0.1 Vault Initialization and Unlock

### Goals

- Implement vault initialization.
- Implement vault unlock.
- Ensure the vault starts locked after restart.

### Person 1 Tasks

Implement:

- First-run initialization.
- Strong master passphrase validation.
- KDF using Argon2id or PBKDF2-HMAC-SHA256.
- Random salt generation.
- Random Data Encryption Key, called DEK.
- DEK encryption using AES-256-GCM.
- Storage of only encrypted DEK and KDF metadata.
- Locked state after every restart.
- Unlock using correct master passphrase.
- Generic error for wrong master passphrase.

Required stored metadata example:

```json
{
  "kdf": "argon2id",
  "kdf_salt_b64": "<salt>",
  "encrypted_dek_b64": "<encrypted DEK>",
  "status": "locked"
}
```

### Person 2 Tasks

- Help test locked-state behavior for KV operations.
- Prepare tests:
  - KV write while locked fails with `VAULT_LOCKED`.
  - KV read while locked fails with `VAULT_LOCKED`.
  - KV delete while locked fails with `VAULT_LOCKED`.

### Person 3 Tasks

- Help test locked-state behavior for Transit operations.
- Prepare tests:
  - Transit key creation while locked fails with `VAULT_LOCKED`.
  - Transit encrypt/decrypt while locked fails with `VAULT_LOCKED`.
  - Signing operations while locked fail with `VAULT_LOCKED`.
- Document vault initialization flow for the report.

### Day 2 Deliverables

- Vault can be initialized.
- Vault can be unlocked with correct master passphrase.
- Wrong master passphrase fails safely.
- Plaintext DEK is never written to disk.

---

## Day 3 — Feature 0.2 Authentication and Sessions

### Goals

- Implement user registration.
- Implement login.
- Implement session validation.
- Implement account lockout.

### Person 1 Tasks

Implement:

- User registration with:
  - Email
  - Passphrase
  - Confirm passphrase
- Unique email check.
- Password strength validation.
- Password hashing using bcrypt or Argon2.
- Login using email and passphrase.
- Session token generation.
- Session expiry, recommended 30 minutes.
- Failed login counter.
- Account lockout for exactly 5 minutes after five consecutive failed login attempts.
- Login rejection during lockout, even with correct passphrase.

User data example:

```json
{
  "email": "alice@example.com",
  "password_hash": "<bcrypt_or_argon2_hash>",
  "failed_attempts": 0,
  "locked_until": null
}
```

### Person 2 Tasks

- Integrate token validation into KV module.
- Ensure invalid or expired token is rejected before path ownership checks.
- Prepare KV authorization helper usage.

### Person 3 Tasks

- Integrate token validation into Transit module.
- Ensure invalid or expired token is rejected before key ownership checks.
- Add authentication explanation to report.
- Prepare screenshots or terminal output for register/login demo.

### Day 3 Deliverables

- User registration works.
- Login returns session token.
- Expired session token is rejected.
- Five failed logins lock the account for 5 minutes.
- Passwords are never stored in plaintext.

---

## Day 4 — Feature 1.1 KV Encrypted Storage

### Goals

- Implement encrypted-at-rest KV storage.
- Ensure tampering is detected.
- Ensure raw files contain no plaintext secret fragments.

### Person 2 Tasks

Implement:

- `write(path, data, token)`.
- `read(path, token)`.
- `delete(path, token)`.
- AES-256-GCM encryption of the full JSON payload using the current DEK.
- Fresh random nonce for every write.
- Storage of only ciphertext, nonce, tag, path, and metadata.
- Direct overwrite of existing paths.
- Authentication tag verification before returning plaintext.
- Safe failure if ciphertext or tag is tampered.

KV storage example:

```json
{
  "path": "secret/alice@example.com/db",
  "nonce_b64": "...",
  "ciphertext_b64": "...",
  "tag_b64": "..."
}
```

### Person 1 Tasks

- Provide safe access to in-memory DEK after vault unlock.
- Review shared encryption/decryption helper functions.
- Add reusable AES-GCM utility if needed.

### Person 3 Tasks

- Write KV encrypted storage explanation for the report.
- Add KV commands or API examples for demo.

### Day 4 Deliverables

- KV write/read round trip returns original JSON exactly.
- KV delete works.
- Raw data files show no plaintext secret fragments.
- Tampered KV ciphertext or tag is rejected.

---

## Day 5 — Feature 1.2 KV Access Control and Feature 2.1/2.2 Transit AES

### Goals

- Complete KV ownership access control.
- Implement named AES key management.
- Implement Transit encrypt/decrypt.

### Person 2 Tasks

Implement KV ownership access control:

- Enforce path format:

```text
secret/<email>/...
```

- Compare token email with email in path prefix.
- Deny access before encryption or decryption if owner does not match.
- Return `PERMISSION_DENIED` for cross-user access.
- Do not disclose whether the target path exists.
- Log denied access attempts with requester email and denied path.
- Ensure invalid or expired token is rejected before authorization checks.

### Person 3 Tasks

Implement Transit AES key management:

- `create_key(key_name, token)`.
- `list_keys(token)`.
- `revoke_key(key_name, token)`.
- Generate random AES-256 key.
- Bind key to:
  - `key_name`
  - owner email
  - `key_usage = "ENCRYPT_DECRYPT"`
- Encrypt key material with DEK before storage.
- Ensure raw AES key is never returned by any API.
- Decide and document duplicate key behavior.

Named key storage example:

```json
{
  "key_name": "my-key",
  "owner_email": "alice@example.com",
  "key_usage": "ENCRYPT_DECRYPT",
  "encrypted_key_material_b64": "<AES key encrypted with the DEK>"
}
```

Implement Transit encrypt/decrypt:

- `encrypt(key_name, plaintext_b64, token)`.
- `decrypt(ciphertext, token)`.
- Verify ownership of the named key.
- Temporarily decrypt AES key using in-memory DEK.
- Encrypt plaintext using AES-256-GCM with fresh random nonce.
- Return self-describing ciphertext:

```text
vault:<key_name>:<base64(nonce+ct+tag)>
```

- Parse key name from ciphertext during decrypt.
- Verify AES-GCM tag before returning plaintext.
- Return plaintext as base64.

### Person 1 Tasks

- Review auth/session integration in KV and Transit.
- Add shared access-denied logging support.
- Fix integration issues between vault state, auth, KV, and Transit.

### Day 5 Deliverables

- User A cannot access User B's KV path.
- Named AES keys can be created, listed, and revoked.
- Transit encrypt/decrypt round trip works.
- Raw AES key material is never returned.
- Tampered Transit ciphertext fails decryption.

---

## Day 6 — Feature 2.3 Transit Access Control, Feature 2.4 Sign/Verify, and Testing

### Goals

- Complete Transit authorization.
- Implement signing and verification.
- Write required tests.

### Person 3 Tasks

Implement Transit access control:

- Store `owner_email` for every named key.
- Compare token email with key owner email.
- Deny non-owner access before cryptographic operations.
- Do not disclose whether the key exists.
- Log denied access attempts with requester email and denied key name.

Implement signing and verification:

- `create_signing_key(key_name, signing_algorithm, token)`.
- `sign(key_name, message_b64, message_type, token)`.
- `verify(key_name, message_b64, message_type, signature_b64, token)`.
- Recommended algorithm: Ed25519.
- Bind signing key to:
  - `key_name`
  - owner email
  - `key_usage = "SIGN_VERIFY"`
  - signing algorithm
- Encrypt private key with DEK before storage.
- Store public key for verification.
- Never return private key through any API.
- Support `message_type = RAW`.
- Support `message_type = DIGEST` if time allows.
- Return structured verify result:

```json
{
  "key_name": "my-signing-key",
  "signature_valid": true,
  "signing_algorithm": "ED25519"
}
```

### Person 1 Tasks

Write tests for:

- Vault initialization stores only encrypted DEK.
- Vault restarts in locked state.
- Wrong master passphrase fails unlock.
- Feature 1 and Feature 2 fail while locked with `VAULT_LOCKED`.
- User registration stores bcrypt or Argon2 password hash only.
- Successful login returns session token.
- Expired session token is rejected.
- Five consecutive failed logins lock account for 5 minutes.

### Person 2 Tasks

Write tests for:

- KV write/read round trip returns original JSON exactly.
- KV data file contains no plaintext secret fragments.
- Tampered KV ciphertext or tag is rejected.
- User A cannot access User B's KV path.
- Invalid token is rejected before path authorization.

### Person 3 Additional Tests

Write tests for:

- Named AES key creation stores only encrypted key material.
- `list_keys` never returns raw key material.
- Transit encrypt/decrypt round trip succeeds for text, JSON, and binary base64.
- Tampered Transit ciphertext fails decryption.
- User A cannot use User B's named key.
- Encrypt/decrypt rejects keys with `SIGN_VERIFY` usage.
- Signing key creation stores encrypted private key only.
- Sign then verify on original message succeeds.
- Verify on tampered message fails.
- Cross-key signature verification fails.
- Sign/verify rejects keys with `ENCRYPT_DECRYPT` usage.

### Day 6 Deliverables

- Transit access control works.
- Sign/verify works.
- Required tests are mostly complete.
- Tamper and cross-user tests pass.

---

## Day 7 — Final Integration, Report, Demo, and Packaging

### Goals

- Fix bugs.
- Finalize documentation.
- Prepare demo.
- Package submission.

### Person 1 Tasks

- Fix integration bugs.
- Finalize `README.md`.
- Include:
  - Installation steps
  - Run commands
  - Example commands
  - Test commands
- Verify vault initialization and authentication flows work end-to-end.

### Person 2 Tasks

- Finalize KV tests.
- Prepare KV screenshots or terminal output.
- Prepare sample encrypted KV data file.
- Verify raw storage files contain no plaintext.
- Help package final test data.

### Person 3 Tasks

- Finalize Transit tests.
- Prepare sample Transit ciphertext.
- Complete final report PDF under:

```text
docs/report/Report_StudentID1_StudentID2_StudentID3.pdf
```

- Prepare 3–5 minute demo video.
- Create or finalize architecture diagram.
- Add task assignment section to report.

### Day 7 Deliverables

- All required tests pass.
- README is complete.
- Report PDF is complete.
- Demo video is ready.
- Final zip package is ready.

Submission package name:

```text
StudentID1_StudentID2_StudentID3.zip
```

---

## 4. Required Demo Checklist

The demo should show:

- [ ] Vault unlock
- [ ] Write a secret
- [ ] Read a secret
- [ ] Denied cross-user secret access
- [ ] Create a named Transit key
- [ ] Encrypt with Transit
- [ ] Decrypt with Transit
- [ ] Denied cross-user key usage
- [ ] Sign a message
- [ ] Verify valid signature
- [ ] Verify tampered message as invalid

---

## 5. Required Test Checklist

At minimum, implement tests for:

- [ ] Vault initialization stores only encrypted DEK.
- [ ] Vault restarts in locked state.
- [ ] Wrong Master Passphrase fails unlock.
- [ ] Feature 1 and Feature 2 fail while locked with `VAULT_LOCKED`.
- [ ] User registration stores bcrypt or Argon2 password hash only.
- [ ] Successful login returns session token.
- [ ] Expired session token is rejected.
- [ ] Five consecutive failed logins lock the account for 5 minutes.
- [ ] KV write/read round trip returns original JSON exactly.
- [ ] KV data file contains no plaintext secret fragments.
- [ ] Tampered KV ciphertext or tag is rejected.
- [ ] User A cannot access User B's KV path.
- [ ] Invalid token is rejected before path authorization.
- [ ] Named AES key creation stores only encrypted key material.
- [ ] `list_keys` never returns raw key material.
- [ ] Transit encrypt/decrypt round trip succeeds for text, JSON, and binary base64.
- [ ] Tampered Transit ciphertext fails decryption.
- [ ] User A cannot use User B's named key.
- [ ] Encrypt/decrypt rejects keys with `SIGN_VERIFY` usage.
- [ ] Signing key creation stores encrypted private key only.
- [ ] Sign then verify on original message succeeds.
- [ ] Verify on tampered message fails.
- [ ] Cross-key signature verification fails.
- [ ] Sign/verify rejects keys with `ENCRYPT_DECRYPT` usage.

---

## 6. Priority Order If Time Is Limited

Complete the project in this order:

1. Vault initialization and unlock
2. User registration and login
3. Session token validation
4. KV encrypted storage
5. KV ownership access control
6. Transit AES key creation
7. Transit encrypt/decrypt
8. Transit ownership access control
9. Sign/verify
10. Tests
11. README
12. Report
13. Demo video

Do **not** start optional extra credit features until all required features, tests, README, report, and demo are complete.

---

## 7. Optional Extra Credit Recommendation

Only attempt optional features if the required implementation is stable.

Recommended optional features, from easiest to hardest:

1. Tamper-evident hash-chained audit log
2. MFA using OTP/TOTP during login
3. KV versioning with overwrite history
4. Transit key rotation with key versions
5. Sharing named keys/secrets using full Policy/ACL system
6. Shamir's Secret Sharing for vault unlock

Extra credit is capped at 1.0 point, so avoid risking required functionality for optional features.
