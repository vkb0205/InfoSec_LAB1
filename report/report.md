# Mini Vault — Project Report (Progress through Feature 0)

**Status of this document:** Covers completed work through **Feature 0.1** (Vault Init & Unlock) and **Feature 0.2** (User Authentication), including **server (REST)**, **client (CLI)**, and **feature** layers. Features 1–2 and advanced extras are outlined per the scientific table of contents but are **not yet implemented** (gates only).

**Canonical TOC source:** `src/docs/report.md`

---

## 1. Front Matter

### 1.1 Team Information

| Field | Value |
|-------|--------|
| Team name | *[fill before submission]* |
| Student ID 1 | *[fill]* |
| Student ID 2 | *[fill]* |
| Student ID 3 | *[fill]* |

### 1.2 Task Assignment

Aligned with `PLAN.md` roles (adjust names/IDs before final PDF):

| Member | Main responsibility | Contribution so far (Feature 0) |
|--------|---------------------|----------------------------------|
| Person 1 | Core vault, auth, sessions | Vault init/unlock, Argon2id + AES-GCM DEK wrap, AuthService, CLI + REST, gates, tests |
| Person 2 | KV secure storage & ACL | Locked-state KV gate tests; KV engine still placeholder |
| Person 3 | Transit, report, demo | Locked-state Transit gate tests; architecture/report draft; Transit still placeholder |

---

## 2. System Architecture

### 2.1 Architecture Diagram

```
                    ┌─────────────────────────────────────┐
                    │           CLIENT LAYER              │
                    │  CLI (main.py)  |  HTTP client      │
                    │  getpass/input  |  curl / browser   │
                    └────────────┬────────────┬───────────┘
                                 │            │
                    one-shot     │            │ long-lived
                    process      │            │ process
                                 ▼            ▼
                    ┌─────────────────────────────────────┐
                    │         ADAPTER / SERVER            │
                    │  argparse CLI  |  FastAPI (serve)   │
                    │  print codes   |  JSON + HTTP codes │
                    └────────────┬────────────────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
        ┌──────────┐      ┌────────────┐     ┌────────────┐
        │  Vault   │      │ AuthService│     │ KV/Transit │
        │  (0.1)   │      │   (0.2)    │     │  gates     │
        └────┬─────┘      └─────┬──────┘     └─────┬──────┘
             │                  │                  │
             ▼                  ▼                  │
   vault_metadata.json    users.json               │
   (wrapped DEK)          (Argon2 hashes)          │
   crypto_utils           sessions in RAM only     │
                                                   ▼
                                          Feature 1/2 crypto
                                          (not implemented yet)
```

### 2.2 System Overview

Mini Vault is a secret-management system inspired by HashiCorp Vault. Target product has two engines:

| Engine | Role | Current progress |
|--------|------|------------------|
| **KV (Feature 1)** | Encrypted-at-rest secrets under owner paths | Service boundary + `VAULT_LOCKED` / session gate only |
| **Transit (Feature 2)** | Encrypt/decrypt/sign/verify as a service; raw keys never leave server | Same gate-only stubs |

**Feature 0** is the security foundation: no KV/Transit crypto may run until (1) vault holds plaintext DEK in memory, and (2) caller presents a valid session. That ordering is already enforced at service boundaries.

### 2.3 Layer Map (implemented)

| Layer | Path | Responsibility |
|-------|------|----------------|
| Client — CLI | `main.py` | Subcommands; secrets via `getpass` / `input`; public error codes only |
| Client — HTTP | any REST client | JSON bodies; `Authorization: Bearer` for session |
| Server — REST | `src/api/app.py` | FastAPI routes; one `Vault` + one `AuthService` per process |
| Core vault | `src/core/vault.py` | Init, unlock, in-memory DEK, lock state |
| Crypto | `src/crypto_utils.py` | Passphrase policy, Argon2id KDF, AES-256-GCM wrap/unwrap, metadata schema |
| Auth | `src/auth/service.py` | Register, login, sessions, lockout |
| Storage | `src/storage/repository.py` | Create-only vault metadata; atomic user store |
| Gates | `src/kv/service.py`, `src/transit/service.py` | Unlock check → session check → (later) ownership/crypto |
| Errors | `src/errors.py` | Stable public codes only |

**Design choice:** SPEC allows CLI alone. Project also ships **REST (`python main.py serve`)** so unlock state and session tokens survive across client calls in one process—closer to a real vault service.

### 2.4 Server vs client (runtime model)

| Aspect | CLI client | REST server |
|--------|------------|-------------|
| Process lifetime | One command → exit | Long-lived (`uvicorn`) |
| Unlock continuity | DEK discarded on exit | DEK kept in `app.state.vault` until restart |
| Session continuity | Token printed then process dies | Tokens in `AuthService._sessions` across HTTP calls |
| After restart | Always locked; sessions gone | Always locked; sessions gone |
| Secret input | `getpass` (never argv) | JSON body only (never query/path) |
| Error surface | stdout: `CODE` | HTTP status + `{"code":"..."}` |

---

## 3. Feature 0: Initialization and Registration

### 3.1 Vault Initialization (0.1)

#### 3.1.1 Requirements (SPEC summary)

1. First run: strong Master Passphrase → KDF → wrap random DEK → store only encrypted material.  
2. After every restart: state defaults to **locked**.  
3. While locked: all KV and Transit operations fail with `VAULT_LOCKED`.  
4. Correct passphrase unlocks: DEK in memory only.  
5. Wrong passphrase: generic failure, no detail leak.  
6. Plaintext DEK never written to disk.

#### 3.1.2 Cryptographic design

Two stages (KDF is **not** an AES input):

**Stage A — Derive wrapping key (KEK)**

| Input | Role |
|-------|------|
| Master Passphrase | secret (never stored) |
| Salt (16 random bytes) | stored on disk (public) |
| Argon2id params | memory / time / parallelism / hash length |

```
passphrase + salt + params  →  Argon2id  →  KEK (32 bytes, RAM only)
```

Default Argon2id parameters (persisted so unlock re-derives identically):

- `memory_cost_kib = 65536`
- `time_cost = 3`
- `parallelism = 1`
- `hash_len = 32`

**Stage B — Wrap the DEK (AES-256-GCM)**

| GCM input | Value |
|-----------|--------|
| key | KEK from Stage A |
| nonce | 12 random bytes (stored; not secret) |
| plaintext | DEK (32 random bytes) |
| AAD | fixed `b"mini-vault:vault-metadata:v1"` |

```
AES-256-GCM.encrypt → ciphertext || tag
```

- **Ciphertext** hides the DEK.  
- **Tag** authenticates ciphertext + AAD + nonce under KEK.  
- Unlock: re-derive KEK → verify tag → obtain DEK. Wrong passphrase → `UNLOCK_FAILED`.

#### 3.1.3 Data on disk

**File:** `data/vault_metadata.json` (create-only; second init → `ALREADY_INITIALIZED`)

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

| Stored | Secret? |
|--------|---------|
| salt, nonce, KDF params, algorithm labels | No |
| ciphertext \|\| tag | Unreadable without KEK |
| Master Passphrase, KEK, plaintext DEK, `status` | **Never on disk** |

Only binary blobs are Base64-encoded. **Status is runtime-only** (not a disk field).

#### 3.1.4 Runtime state

| Condition | Status |
|-----------|--------|
| No metadata file | `uninitialized` |
| Metadata exists, `_dek is None` | `locked` |
| DEK held in process memory | `unlocked` |

```
Init:   write metadata → _dek stays None → locked
Unlock: unwrap DEK → _dek = bytes → unlocked
Restart / new process: _dek = None → locked again
```

No explicit `lock` API; lock = absence of DEK in current process.

#### 3.1.5 Allowed while locked vs unlocked

| Operation | Vault locked | Vault unlocked |
|-----------|--------------|----------------|
| `status` / `init` / `unlock` | Allowed (0.1) | Allowed |
| `register` / `login` / session | Allowed (0.2; no DEK) | Allowed |
| **All KV** | **`VAULT_LOCKED`** | Needs session + ownership (Feature 1) |
| **All Transit** | **`VAULT_LOCKED`** | Needs session + ownership (Feature 2) |

#### 3.1.6 Client interface (CLI)

```bash
python main.py status
python main.py init      # getpass Master Passphrase
python main.py unlock    # getpass Master Passphrase
```

Secrets never accepted as command-line arguments. Expected failures print only public codes (`INVALID_INPUT`, `ALREADY_INITIALIZED`, `UNLOCK_FAILED`).

#### 3.1.7 Server interface (REST)

```bash
python main.py serve     # default http://127.0.0.1:8000
```

| Method | Path | Body | Success |
|--------|------|------|---------|
| `GET` | `/v1/status` | — | `{"status":"uninitialized"\|"locked"\|"unlocked"}` |
| `POST` | `/v1/init` | `{"passphrase":"..."}` | `{"result":"initialized","status":"locked"}` |
| `POST` | `/v1/unlock` | `{"passphrase":"..."}` | `{"status":"unlocked"}` |

One `Vault` lives in `app.state.vault`. After unlock, later `GET /v1/status` stays `unlocked` until process stop. **Every server restart locks the vault again.**

HTTP error mapping (body always `{"code": "..."}` only):

| Code | Typical HTTP |
|------|----------------|
| `INVALID_INPUT` | 400 |
| `ALREADY_INITIALIZED` | 409 |
| `UNLOCK_FAILED` | 401 |
| `VAULT_LOCKED` | 403 |

#### 3.1.8 Call chains

**Init**

```
validate passphrase → random salt, DEK, nonce
→ Argon2id → KEK → AES-GCM wrap DEK
→ construct_metadata → MetadataRepository.create (atomic, create-only)
→ discard DEK/KEK; stay locked
```

**Unlock**

```
read + validate metadata → decode salt, nonce, ciphertext||tag
→ Argon2id(passphrase, stored params) → KEK
→ AES-GCM decrypt (tag verify) → DEK in RAM
→ any failure → UNLOCK_FAILED
```

#### 3.1.9 Error codes (0.1)

| Code | When |
|------|------|
| `INVALID_INPUT` | Weak passphrase, bad argv, invalid init input |
| `ALREADY_INITIALIZED` | Metadata already exists |
| `UNLOCK_FAILED` | Wrong passphrase, bad/tampered metadata, GCM fail (generic) |
| `VAULT_LOCKED` | KV/Transit (or `get_dek`) while locked |

#### 3.1.10 Implementation map (0.1)

| Topic | Primary files |
|-------|----------------|
| State machine | `src/core/vault.py` |
| KDF, GCM, schema | `src/crypto_utils.py` |
| Disk I/O | `src/storage/repository.py` |
| REST | `src/api/app.py` |
| CLI | `main.py` |
| Flow notes | `src/docs/flow_ft_0.md` |

---

### 3.2 User Authentication (0.2)

#### 3.2.1 Requirements (SPEC summary)

1. Register: email + passphrase + confirmation; unique email; strong passphrase.  
2. Hash user passphrases with Argon2 or bcrypt (not plain SHA).  
3. Login issues a session token; tokens expire (30 minutes implemented).  
4. Feature 1/2 require a valid session token.  
5. Five consecutive failed logins → account locked **exactly 5 minutes**; correct password still fails during lockout.

#### 3.2.2 Registration

1. Canonicalize email: strip + casefold; basic format check.  
2. Require matching confirmation.  
3. Enforce passphrase strength (same policy helper as master passphrase: ≥12 chars, lower, upper, digit, symbol).  
4. Hash with `argon2.PasswordHasher`.  
5. Persist via `UserRepository.create_account` (duplicate → `DUPLICATE_USER`).

#### 3.2.3 User store on disk

**File:** `data/users.json`

| Field | Meaning |
|-------|---------|
| `email` | Canonical email |
| `password_hash` | Argon2 verification hash only |
| `failed_attempts` | Consecutive failed logins |
| `locked_until` | UTC ISO timestamp or `null` |

**Never stored:** plaintext passphrases, session tokens.

#### 3.2.4 Login and sessions

```
login(email, passphrase)
  → if locked_until > now → ACCOUNT_LOCKED
  → verify Argon2 hash
  → fail: increment failed_attempts; at 5 set locked_until = now+5min → INVALID_CREDENTIALS
  → ok: reset counters; issue opaque token (secrets.token_urlsafe)
  → _sessions[token] = (email, now + 30 minutes)   # RAM only
  → return token
```

`validate_session(token)` → canonical email, or `UNAUTHENTICATED` if missing/unknown/expired.

**Sessions are process-local.** Restart clears `_sessions`. Account lockout timestamps **do** survive restart (on disk).

#### 3.2.5 Client interface (CLI)

```bash
python main.py register   # email + passphrase + confirm prompts → registered
python main.py login      # prints one session token
```

Note: one-shot CLI exits after login, so the token is only useful if a long-lived component holds `AuthService` (the REST server does).

#### 3.2.6 Server interface (REST)

| Method | Path | Input | Success |
|--------|------|-------|---------|
| `POST` | `/v1/auth/register` | `{email, passphrase, confirmation}` | `{"result":"registered"}` |
| `POST` | `/v1/auth/login` | `{email, passphrase}` | `{"token":"..."}` |
| `GET` | `/v1/auth/session` | `Authorization: Bearer <token>` | `{"email":"..."}` |

`serve` holds one shared `AuthService` so tokens work across HTTP calls until restart.

HTTP mapping additions:

| Code | Typical HTTP |
|------|----------------|
| `DUPLICATE_USER` | 409 |
| `INVALID_CREDENTIALS` | 401 |
| `ACCOUNT_LOCKED` | 403 |
| `UNAUTHENTICATED` | 401 |

#### 3.2.7 Protected operation ordering (SPEC §4)

For every Feature 1 and Feature 2 call:

```
1. Vault locked?     → VAULT_LOCKED
2. Session invalid?  → UNAUTHENTICATED
3. Not owner?        → access denied (Feature 1.2 / 2.3 — later)
4. Else              → perform operation
```

Feature 0.2 implements steps 1–2 at the KV/Transit service boundary; ownership reserved for later features.

#### 3.2.8 Parallel mental models (0.1 vs 0.2)

| Concept | Vault (0.1) | Auth (0.2) |
|---------|-------------|------------|
| Long-term secret on disk | Wrapped DEK | Argon2 password hash |
| Capability in RAM | Plaintext DEK | Session token map |
| After process restart | Locked (no DEK) | All sessions invalid |
| Survives restart on disk | Metadata envelope | Users + lockout timers |
| Public “am I ready?” | `status` | `GET /v1/auth/session` |

#### 3.2.9 Implementation map (0.2)

| Topic | Primary files |
|-------|----------------|
| Register / login / session | `src/auth/service.py` |
| User store | `src/storage/repository.py` |
| REST | `src/api/app.py` |
| CLI | `main.py` |
| Flow notes | `src/docs/flow_ft_0_2.md` |

---

### 3.3 Security decisions (Feature 0)

1. Master Passphrase and user passphrases are never written to disk.  
2. DEK is stored only as AES-GCM ciphertext \|\| tag.  
3. Plaintext DEK exists only in memory after successful unlock.  
4. Vault unlock **status** is never persisted (avoids lying after restart).  
5. Session tokens are never persisted.  
6. Account lockout state **is** persisted so lockout cannot be cleared by restart alone.  
7. Wrong unlock and bad metadata collapse to one public code (`UNLOCK_FAILED`).  
8. Passphrases are not accepted via argv; REST uses JSON body only (not query string).  
9. API/CLI errors never return DEK, KEK, password hashes, or stack traces for expected failures.  
10. `data/vault_metadata.json` and `data/users.json` are gitignored runtime files.

---

## 4. Feature 1: Secure Storage (KV Engine)

> **Progress:** Not implemented. `KVService` enforces unlock then optional session validation, then raises `NotImplementedError` for real write/read/delete.

### 4.1 Encrypted-at-Rest Storage (1.1) — planned

- AES-256-GCM of full JSON payload with current DEK.  
- Fresh random nonce per write.  
- Disk: ciphertext, nonce, tag, path metadata only.  
- Tag verify before any plaintext return; tamper → reject.

### 4.2 Ownership-Based Access Control (1.2) — planned

- Path form: `secret/<email>/...`  
- Token email must match path owner before crypto.  
- Cross-user → `PERMISSION_DENIED` without existence leak; log denied attempts.

---

## 5. Feature 2: Transit Engine (Encryption & Signing)

> **Progress:** Not implemented. `TransitService` same gate pattern as KV; crypto APIs stubbed.

### 5.1 Named Key Management (2.1) — planned

- Random AES-256 keys bound to name, owner, `ENCRYPT_DECRYPT`.  
- Key material encrypted with DEK; never returned by API.

### 5.2 Encryption and Decryption APIs (2.2) — planned

- Ciphertext form: `vault:<key_name>:<base64(nonce+ct+tag)>`.  
- Round-trip integrity; tamper detection via GCM tag.

### 5.3 Named-Key Access Control (2.3) — planned

- Owner-only encrypt/decrypt; denied attempts logged.

### 5.4 Sign and Verify Service (2.4) — planned

- Asymmetric keys (Ed25519 and/or RSA); private key wrapped with DEK.  
- Sign/verify without exposing private key; structured `signature_valid` result.

---

## 6. Advanced Features (Optional)

> **Progress:** None attempted. Extra credit deferred until required features, tests, README, report, and demo are complete (`PLAN.md` priority order).

Candidates (SPEC): Shamir unlock, MFA/TOTP, KV versioning, Transit key rotation, Policy/ACL sharing, hash-chained audit log.

---

## 7. Demonstration and Testing

### 7.1 How to run (current progress)

**Setup**

```bash
pip install -r requirements.txt
```

**CLI (Feature 0.1 / 0.2)**

```bash
python main.py status
python main.py init
python main.py unlock
python main.py register
python main.py login
```

**REST demo (recommended for unlock + session continuity)**

Terminal 1:

```bash
python main.py serve
```

Terminal 2 (PowerShell: prefer `curl.exe` or `Invoke-RestMethod`):

```powershell
Invoke-RestMethod http://127.0.0.1:8000/v1/status
Invoke-RestMethod http://127.0.0.1:8000/v1/init -Method POST -ContentType "application/json" -Body '{"passphrase":"Str0ng!Passphrase123"}'
Invoke-RestMethod http://127.0.0.1:8000/v1/unlock -Method POST -ContentType "application/json" -Body '{"passphrase":"Str0ng!Passphrase123"}'
Invoke-RestMethod http://127.0.0.1:8000/v1/status
# → unlocked

Invoke-RestMethod http://127.0.0.1:8000/v1/auth/register -Method POST -ContentType "application/json" -Body '{"email":"user@example.com","passphrase":"Str0ng!Passphrase123","confirmation":"Str0ng!Passphrase123"}'
$r = Invoke-RestMethod http://127.0.0.1:8000/v1/auth/login -Method POST -ContentType "application/json" -Body '{"email":"user@example.com","passphrase":"Str0ng!Passphrase123"}'
Invoke-RestMethod http://127.0.0.1:8000/v1/auth/session -Headers @{ Authorization = "Bearer $($r.token)" }
```

Swagger UI: `http://127.0.0.1:8000/docs`

**Restart server** → vault `locked`, previous tokens `UNAUTHENTICATED`.

### 7.2 Test data files

| Artifact | Status |
|----------|--------|
| Encrypted KV data file | Not yet (Feature 1) |
| Sample Transit ciphertext | Not yet (Feature 2) |
| Runtime vault metadata | Generated at `data/vault_metadata.json` after init (gitignored) |
| User store | Generated at `data/users.json` after register (gitignored) |

### 7.3 Demo screenshots

| Demo item (SPEC) | Status |
|------------------|--------|
| Vault unlock | Ready (CLI + REST) |
| Write/read secret | Pending Feature 1 |
| Denied cross-user secret | Pending Feature 1.2 |
| Create named key / encrypt / decrypt | Pending Feature 2 |
| Denied cross-user key | Pending Feature 2.3 |
| Sign / verify / tampered message | Pending Feature 2.4 |
| Register / login / session | Ready (CLI + REST) |
| Locked vault rejects KV/Transit | Covered by automated gate tests |

Screenshots for Feature 0 can be captured from CLI output and Swagger/HTTP responses; full product demo video waits for Features 1–2.

### 7.4 Automated validation

```bash
pytest
```

Covered areas (Feature 0):

- Metadata contract; no plaintext DEK/passphrase on disk  
- Create-only init; restart locked behavior  
- Correct / incorrect unlock; generic `UNLOCK_FAILED`  
- KDF parameter bounds  
- Locked KV/Transit gates  
- Register/login/session; expiry; restart invalidates sessions  
- Five-failure lockout (5 minutes)  
- CLI prompt-only secrets; REST Feature 0.1 and 0.2 routes  
- Auth ordering before KV/Transit downstream  

Representative commands:

```bash
pytest tests/test_vault_initialization.py tests/test_vault_unlock.py tests/test_cli_init_unlock.py tests/test_api_vault_0_1.py tests/test_auth_service.py tests/test_auth_cli.py tests/test_api_auth_0_2.py tests/test_locked_kv_gate.py tests/test_auth_kv_gate.py
```

---

## 8. Conclusion (current progress)

Feature **0.1** establishes a **sealed root key** (wrapped DEK) and a **process-local unlock model** that matches locked-after-restart. Feature **0.2** establishes **user identity** with Argon2 hashing, expiring RAM-only sessions, and account lockout.

**Server** (`serve` / FastAPI) keeps unlock and sessions across HTTP calls; **client** CLI is one-shot and prompt-safe. Together they enforce the mandatory order for later work:

**unlock vault → authenticate user → authorize ownership → use KV/Transit.**

No plaintext DEK, master passphrase, user passphrase, or session token is persisted. Public interfaces expose only stable status strings and error codes.

**Next:** Feature 1.1 KV encrypted storage, then 1.2 ownership ACL, then Transit 2.1–2.4, then full demo evidence and final PDF under `docs/report/`.

---

*End of progress report — Feature 0.1 and 0.2 complete; Features 1–2 pending.*
