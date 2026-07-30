# Feature 0.2 — User Authentication: Flow

## Role

Register users, verify passphrases with Argon2, issue process-local session tokens, lock accounts after 5 failed logins, validate sessions for later KV/Transit.

## Modules

| Module | Role |
|--------|------|
| `main.py` | CLI: `register` / `login`; `serve` holds AuthService |
| `src/api/app.py` | REST: register / login / session |
| `src/auth/service.py` | register, login, validate_session, lockout |
| `src/storage/repository.py` | `UserRepository` → `data/users.json` |
| `src/kv/service.py`, `src/transit/service.py` | lock first, then session validate |

---

## What is stored where

| Data | Where | Survives restart? |
|------|--------|-------------------|
| email, Argon2 hash, failed_attempts, locked_until | `data/users.json` | yes |
| session token → (email, expiry) | `AuthService._sessions` RAM | **no** |
| plaintext passphrase | nowhere | — |

Same idea as vault status: **identity proof in RAM**, account record on disk.

---

## Functional flow

### 1. Register

```
email + passphrase + confirmation
  → canonicalize email (strip, casefold)
  → strength check (same policy as master passphrase helper)
  → Argon2 hash
  → UserRepository.create_account (reject DUPLICATE_USER)
```

Disk: hash only. No session yet.

### 2. Login

```
email + passphrase
  → load account
  → if locked_until > now → ACCOUNT_LOCKED
  → verify Argon2
  → fail: failed_attempts++; at 5 set locked_until = now+5min → INVALID_CREDENTIALS
  → ok: reset counters; token = secrets; _sessions[token] = (email, now+30min)
  → return token
```

### 3. Validate session (for Feature 1/2 later)

```
Bearer token
  → missing/unknown/expired → UNAUTHENTICATED
  → ok → canonical email
```

### 4. Ordering on protected ops

```
1. vault.is_locked()?     → VAULT_LOCKED
2. validate_session(token)? → UNAUTHENTICATED
3. ownership / crypto work
```

---

## REST (long-lived `serve`)

| Method | Path | Body / header | Success |
|--------|------|---------------|---------|
| `POST` | `/v1/auth/register` | `{email, passphrase, confirmation}` | `{"result":"registered"}` |
| `POST` | `/v1/auth/login` | `{email, passphrase}` | `{"token":"..."}` |
| `GET` | `/v1/auth/session` | `Authorization: Bearer <token>` | `{"email":"..."}` |

Server restart → all sessions invalid (new `AuthService`, empty `_sessions`).  
Account lockout timestamps on disk still apply after restart.

---

## CLI

```
python main.py register   # prompts email + passphrase + confirm → registered
python main.py login      # prompts email + passphrase → prints one token
```

Note: one-shot CLI login prints token then exits — token dies with process.  
Use **REST `serve`** to keep sessions across calls (demo Feature 0.2 properly).

---

## Error codes

| Code | When |
|------|------|
| `INVALID_INPUT` | bad email, weak passphrase, confirm mismatch |
| `DUPLICATE_USER` | email already registered |
| `INVALID_CREDENTIALS` | bad login / unknown user |
| `ACCOUNT_LOCKED` | 5 fails → 5 minute lockout |
| `UNAUTHENTICATED` | missing/bad/expired session token |

---

## Call chains

### register

```
AuthService.register
  ├─ canonical_email
  ├─ validate_master_passphrase (strength)
  ├─ PasswordHasher.hash
  └─ UserRepository.create_account
```

### login

```
AuthService.login
  ├─ read account / lockout check
  ├─ hasher.verify
  ├─ replace_account (counters)
  └─ _sessions[token] = (email, expiry)
```

### session

```
GET /v1/auth/session
  └─ AuthService.validate_session(bearer)
```
