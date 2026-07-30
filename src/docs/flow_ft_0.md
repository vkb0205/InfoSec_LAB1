# Feature 0.1 — Vault Init & Unlock: Flow and Call Chains

## Role

Create vault metadata, wrap the DEK with the master passphrase, stay locked by default, unlock only with the correct passphrase, and gate KV/Transit while locked.

**Report note (status + restart):** `src/docs/report.md`

## Modules

| Module | Role |
|--------|------|
| `main.py` | CLI: `init` / `unlock` / `status` / `serve` |
| `src/api/app.py` | REST: `GET /v1/status`, `POST /v1/init`, `POST /v1/unlock` |
| `src/core/vault.py` | State machine: init, unlock, `get_dek` |
| `src/crypto_utils.py` | Passphrase policy, Argon2id, AES-GCM wrap/unwrap, metadata |
| `src/storage/repository.py` | Create-only `vault_metadata.json` |
| `src/kv/service.py`, `src/transit/service.py` | `VAULT_LOCKED` gate only |

---

## Functional Flow

Aligned with project PDF / SPEC Feature 0.1. Numbered steps use PDF language. **Impl detail** = how this repo does each step.

### 1. First run (init)

Enter a sufficiently strong Master Passphrase. Derive a key from the passphrase using a KDF (Argon2id/PBKDF2, with a randomly generated salt stored separately).

**Impl detail:**
- CLI: `python main.py init` → `getpass` → `Vault.initialize(passphrase)`
- If `data/vault_metadata.json` already exists → refuse second init → `ALREADY_INITIALIZED` (stops overwriting root keys)
- Strength check (`validate_master_passphrase`): ≥12 chars, lowercase + uppercase + digit + symbol; fail → `INVALID_INPUT` (no crypto yet)
- This repo uses **Argon2id** only (`derive_wrapping_key`)
- Random salt = 16 bytes, stored separately on disk (base64)
- Derived key = **KEK / wrapping key** — exists only in memory during the operation; never written to disk
- KDF params checked by `validate_kdf_parameters` before derive

### 2. Generate DEK, encrypt, write to disk

Generate a random Data Encryption Key (DEK), encrypt the DEK with the derived key (AES-256-GCM), and write it to disk (encrypted DEK + salt).

Crypto is **two stages**. KDF params are **not** AES inputs.

#### Stage A — derive the key (from step 1; needed before wrap)

| Input | Role |
|-------|------|
| Master Passphrase | secret |
| salt (16 bytes) | unique KDF input |
| KDF params (memory/time/parallelism/hash_len) | configure Argon2id only |

```
passphrase + salt + KDF params
    → Argon2id
    → derived key (KEK / wrapping key)
```

KEK stays in memory for the wrap; never written to disk.

#### Stage B — encrypt the DEK (AES-256-GCM only)

Random material for this stage:
- DEK (32 bytes) — plaintext to protect
- nonce (12 bytes) — unique per GCM encryption; **not secret**; must be stored for unlock

| GCM input | Role |
|-----------|------|
| **key (KEK)** | does **both** jobs below (encrypt + auth) |
| **nonce** | 12 random bytes |
| **plaintext** | DEK only |
| **AAD** | fixed `b"mini-vault:vault-metadata:v1"` (authenticated, not encrypted) |

**Not** GCM inputs: KDF params, salt, algorithm name strings (`"argon2id"`, `"aes-256-gcm"`).

What AES-256-GCM actually does (one `encrypt()` call):

| Output | What it is | Secret? |
|--------|------------|---------|
| **ciphertext** | `encrypt(KEK, nonce, DEK)` — only the DEK is encrypted (~32 bytes) | unreadable without KEK |
| **tag** | MAC / integrity seal under KEK over `(ciphertext, AAD, nonce)` — **not** an encryption of the tag | public bytes; unforgeable without KEK |

```
KEK ──┬──► encrypt(DEK)              → ciphertext
      └──► auth(ciphertext, AAD, nonce) → tag   (not encrypt(tag))

result = ciphertext || tag   (library appends tag; ~48 bytes total)
```

- Ciphertext hides the DEK.
- Tag answers: “OK to trust this blob under this KEK/nonce/AAD?”
- Tag is **not** a second ciphertext. Wrong passphrase / flipped bits / wrong AAD → tag check fails later.

#### Write to disk

`MetadataRepository.create()` → `data/vault_metadata.json` (create-only).

| On disk | Secret? | Why stored | Used later for |
|---------|---------|------------|----------------|
| `kdf.salt_b64` | no | PDF: salt stored separately | Stage A on unlock |
| `kdf` cost params | no | re-run Argon2id same way | Stage A on unlock |
| `aead.nonce_b64` | no | GCM needs **same** nonce to decrypt | Stage B on unlock |
| `aead.ciphertext_and_tag_b64` | ct unreadable w/o KEK | PDF: encrypted DEK = `ciphertext \|\| tag` | Stage B on unlock |
| `kdf.algorithm` / `aead.algorithm` / `schema_version` | no | labels for strict validate | reject unknown format |

- Only binary blobs use base64 (`salt`, `nonce`, `ciphertext||tag`). Ints / algorithm names stay plain JSON.
- **Never on disk:** plaintext DEK, Master Passphrase, KEK.
- After init, `_dek` stays `None` → still **locked** (unlock is step 4)

```
Stage A:  passphrase + salt + KDF params → Argon2id → KEK
Stage B:  KEK + nonce + DEK + AAD      → AES-256-GCM → ciphertext || tag
Disk:     salt + KDF params + nonce + ciphertext||tag
          (no passphrase, no KEK, no plaintext DEK)
RAM:      discard DEK + KEK; vault stays locked
```

### 3. Every restart → default state is locked

On every restart, the default state is `"locked"` — both Feature 1 (KV) and Feature 2 (Transit) refuse to operate.

**Impl detail:**
- Locked = no plaintext DEK in process memory (`_dek is None`)
- Runtime status is **not** persisted on disk; restart always drops RAM → locked
- No metadata → **uninitialized**; metadata present, no in-memory DEK → **locked**; DEK in RAM → **unlocked**
- While locked, Feature 1 and Feature 2 APIs fail with `VAULT_LOCKED`:
  - KV: `write` / `read` / `delete`
  - Transit: key ops, encrypt/decrypt, sign/verify
- `Vault.get_dek()` while locked → `VAULT_LOCKED`

### 4. Unlock with correct Master Passphrase

Re-entering the correct Master Passphrase → re-derive the key → decrypt the DEK → transition to `"unlocked"`.

**Order matters.** Nonce and AAD are **inputs you already have** — not recovered by decrypting the blob.

#### What unlock already has (before GCM)

| Piece | Source |
|-------|--------|
| salt + KDF params | disk metadata |
| **nonce** | disk `aead.nonce_b64` (written at init) |
| **ciphertext \|\| tag** | disk `aead.ciphertext_and_tag_b64` |
| **AAD** | fixed in code (`METADATA_AAD`) — not on disk, not inside ciphertext |
| Master Passphrase | user via `getpass` |
| KEK | re-derived (not on disk) |
| DEK | **only output** if tag OK |

#### Steps

1. CLI: `python main.py unlock` → `getpass` → `Vault.unlock(passphrase)`
2. Read + strict-validate metadata → `b64_decode` salt, nonce, `ciphertext||tag`
3. **Stage A again:** `KEK = Argon2id(passphrase, salt, stored KDF params)`
4. **Stage B unwrap** — `AESGCM.decrypt(KEK, nonce, ciphertext||tag, AAD)` internally:
   - recompute tag from `(KEK, nonce, ciphertext, AAD)`
   - compare to stored tag
   - **fail** → stop, no DEK (`InvalidTag` → `UNLOCK_FAILED`)
   - **ok** → decrypt ciphertext → plaintext DEK
5. `_dek` in memory only (process-local) → **unlocked**

Wrong Master Passphrase → wrong KEK → tag mismatch → generic `UNLOCK_FAILED` (no detail: KDF vs tag vs key).

```
CLI unlock → passphrase
  → read disk: salt, KDF params, nonce, ciphertext||tag
  → AAD from code (fixed)
  → KEK = Argon2id(passphrase, salt, params)     # Stage A
  → verify tag first, then ciphertext → DEK      # Stage B (library does both)
  → _dek in RAM → unlocked
  any failure → UNLOCK_FAILED (generic)
```

**Not this:** decrypt blob → get nonce + DEK + AAD → then check tag.  
**This:** already have nonce + AAD + ciphertext||tag + KEK → check tag → then DEK.

### Data contract

PDF sketch:
```json
{
  "kdf": "argon2id",
  "kdf_salt_b64": "<salt>",
  "encrypted_dek_b64": "<encrypted DEK>",
  "status": "locked"
}
```

This repo (same intent, richer envelope):
```json
{
  "schema_version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "salt_b64": "<salt>",
    "memory_cost_kib": 65536,
    "time_cost": 3,
    "parallelism": 1,
    "hash_len": 32
  },
  "aead": {
    "algorithm": "aes-256-gcm",
    "nonce_b64": "<nonce>",
    "ciphertext_and_tag_b64": "<encrypted DEK>"
  }
}
```

| PDF field | Code field |
|-----------|------------|
| `kdf` / `kdf_salt_b64` | `kdf.algorithm` / `kdf.salt_b64` |
| `encrypted_dek_b64` | `aead.ciphertext_and_tag_b64` |
| `status: "locked"` | runtime only (`_dek is None`), not on disk |

### Error cases

| Case | Behavior |
|------|----------|
| Wrong Master Passphrase | DEK decryption fails → generic `UNLOCK_FAILED`, no detail disclosed |
| Feature 1 or Feature 2 API while locked | `VAULT_LOCKED` |
| Weak Master Passphrase on init | `INVALID_INPUT` |
| Init when already initialized | `ALREADY_INITIALIZED` |

### Acceptance criteria

- Plaintext DEK must never be written to disk
- After a restart, state must always be locked until the correct Master Passphrase is entered
- Wrong Master Passphrase never reveals whether KDF, tag, or key validation failed

Public codes: `INVALID_INPUT` · `ALREADY_INITIALIZED` · `UNLOCK_FAILED` · `VAULT_LOCKED`

---

## Call chains

### `init`

```
main.main()
  └─ getpass.getpass()
  └─ Vault.initialize(passphrase)
       ├─ Vault.is_initialized()
       │    └─ MetadataRepository.exists()
       ├─ validate_master_passphrase(passphrase)          # crypto_utils
       ├─ random_salt()                                   # crypto_utils
       ├─ random_dek()                                    # crypto_utils
       ├─ random_nonce()                                  # crypto_utils
       ├─ derive_wrapping_key(passphrase, salt)           # crypto_utils
       │    ├─ validate_kdf_parameters(...)
       │    └─ argon2.hash_secret_raw(...)                # derived key (KEK)
       ├─ wrap_dek(wrapping_key, dek, nonce)              # crypto_utils
       │    └─ AESGCM.encrypt(nonce, dek, METADATA_AAD)
       ├─ construct_metadata(salt, nonce, ct+tag)         # crypto_utils
       │    ├─ b64_encode(salt/nonce/ct)
       │    └─ validate_metadata(metadata)
       │         ├─ b64_decode(...)
       │         └─ validate_kdf_parameters(...)
       └─ MetadataRepository.create(metadata)
            ├─ validate_metadata(metadata)
            ├─ tempfile + write + fsync
            └─ os.link(tmp → vault_metadata.json)         # create-only
       # finally: clear local dek/wrapping_key; _dek stays None (locked)
```

### `unlock`

```
main.main()
  └─ getpass.getpass()
  └─ Vault.unlock(passphrase)
       ├─ self._dek = None                                # force locked first
       ├─ MetadataRepository.read()
       │    ├─ json.load(vault_metadata.json)
       │    └─ validate_metadata(data)
       ├─ extract_metadata_fields(metadata)               # crypto_utils
       │    ├─ validate_metadata(...)
       │    └─ b64_decode(salt, nonce, ct+tag)
       ├─ derive_wrapping_key(passphrase, salt, kdf params)
       │    ├─ validate_kdf_parameters(...)
       │    └─ hash_secret_raw(...)                       # re-derive key
       ├─ unwrap_dek(wrapping_key, nonce, ct+tag)         # crypto_utils
       │    └─ AESGCM.decrypt(... METADATA_AAD)           # InvalidTag → fail
       └─ self._dek = bytes(dek)                          # unlocked in RAM
       # on any crypto/meta/IO error → UnlockFailedError
```

### `status`

```
main.main()
  └─ vault_status(vault)                 # src/api/app.py (shared with REST)
       ├─ Vault.is_initialized() → MetadataRepository.exists()
       └─ Vault.is_locked()      → (_dek is None)
  # prints: uninitialized | locked | unlocked
```

### REST (`serve`) — same Vault, long-lived process

```
main.main() serve
  └─ create_app(vault=same Vault instance)
  └─ uvicorn.run(...)                    # process stays up

Client                          Server (one Vault in app.state)
GET  /v1/status            →    vault_status(vault) → {"status": ...}
POST /v1/init  {passphrase}→    Vault.initialize → {"result":"initialized","status":"locked"}
POST /v1/unlock {passphrase}→   Vault.unlock → {"status":"unlocked"}
                                # later GET /status still unlocked (same process)
VaultError                 →    {"code":"UNLOCK_FAILED"|...}  (no DEK, no passphrase echo)
```

Why REST matters for status: CLI one-shot exits after unlock → DEK gone.  
Server keeps `_dek` in RAM across HTTP calls until process restart → locked again.

### Protected ops (gate only in 0.1)

```
KVService.write/read/delete(vault, ...)
  └─ if vault.is_locked(): raise VaultLockedError
  └─ else: NotImplementedError   # real KV later

TransitService.*(vault, ...)
  └─ same: is_locked() → VAULT_LOCKED, else NotImplementedError
```

### `get_dek` (for later features)

```
Vault.get_dek()
  └─ if _dek is None: raise VaultLockedError
  └─ return bytes(_dek)
```

### Error mapping

| Call site | Raised |
|-----------|--------|
| weak passphrase / bad init input | `InvalidInputError` |
| metadata already exists | `AlreadyInitializedError` |
| bad meta / wrong passphrase / GCM fail | `UnlockFailedError` |
| locked vault access | `VaultLockedError` |
| CLI `except VaultError...` | prints `exc.code`, exit 1 |
