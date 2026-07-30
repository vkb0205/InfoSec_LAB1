# Feature 0.1 — Vault Init & Unlock: Flow and Call Chains

## Role

Create vault metadata, wrap the DEK with the master passphrase, stay locked by default, unlock only with the correct passphrase, and gate KV/Transit while locked.

## Modules

| Module | Role |
|--------|------|
| `main.py` | CLI: `init` / `unlock` / `status` |
| `src/core/vault.py` | State machine: init, unlock, `get_dek` |
| `src/crypto_utils.py` | Passphrase policy, Argon2id, AES-GCM wrap/unwrap, metadata |
| `src/storage/repository.py` | Create-only `vault_metadata.json` |
| `src/kv/service.py`, `src/transit/service.py` | `VAULT_LOCKED` gate only |

## High-level flows

### Init

```
CLI init → passphrase
  → Vault.initialize()
      → reject if metadata exists (ALREADY_INITIALIZED)
      → validate_master_passphrase (≥12, lower/upper/digit/symbol)
      → random salt(16) + DEK(32) + nonce(12)
      → KEK = Argon2id(passphrase, salt)
      → wrap DEK with AES-256-GCM + AAD "mini-vault:vault-metadata:v1"
      → MetadataRepository.create() → data/vault_metadata.json
      → _dek stays None (still locked)
```

### Unlock

```
CLI unlock → passphrase
  → Vault.unlock()
      → read + strict-validate metadata
      → KEK = Argon2id(passphrase, stored params)
      → unwrap DEK (GCM must authenticate)
      → _dek in memory only (process-local)
  any failure → UNLOCK_FAILED (generic)
```

### State

- No metadata → **uninitialized**
- Metadata, no in-memory DEK → **locked** (default after init/restart)
- In-memory DEK → **unlocked**
- `get_dek()` / KV / Transit while locked → **VAULT_LOCKED**

### Public errors

`INVALID_INPUT` · `ALREADY_INITIALIZED` · `UNLOCK_FAILED` · `VAULT_LOCKED`

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
       │    └─ argon2.hash_secret_raw(...)                # KEK
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
       # finally: clear local dek/wrapping_key; _dek stays None
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
       │    └─ hash_secret_raw(...)
       ├─ unwrap_dek(wrapping_key, nonce, ct+tag)         # crypto_utils
       │    └─ AESGCM.decrypt(... METADATA_AAD)           # InvalidTag → fail
       └─ self._dek = bytes(dek)                          # unlocked in RAM
       # on any crypto/meta/IO error → UnlockFailedError
```

### `status`

```
main.main()
  └─ _status(vault)
       ├─ Vault.is_initialized() → MetadataRepository.exists()
       └─ Vault.is_locked()      → (_dek is None)
  # prints: uninitialized | locked | unlocked
```

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
