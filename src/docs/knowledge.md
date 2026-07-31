## KDF = Key Derivation Function
- Takes secret (passphrase) + salt + params → outputs fixed-length crypto key.
### Why
Passphrases weak / wrong size for AES. KDF:
- stretches passphrase into proper key bytes (e.g. 32 for AES-256)
- slows brute-force (memory/time cost)
- salt stops rainbow tables / same-passphrase same-key
### In Mini Vault (0.1)
```
Master Passphrase 
→ Argon2id (or PBKDF2-HMAC-SHA256) 
→ wrapping key 
→ AES-256-GCM wrap/unwrap DEK.
```
- Disk keeps: KDF name, salt, params — not wrapping key or passphrase.
- Common KDFs

|Name|	Notes|
|---|---|
|Argon2id|	modern; memory-hard; preferred here|
|PBKDF2|	older; many iterations HMAC|
|scrypt|	also memory-hard|

*Not KDF: plain SHA-256 of password (too fast, no stretch).*

### `validate_kdf_parameters`

**Where:** `src/crypto_utils.py:94`

**Job:** Guard Argon2id inputs before derive / before trust metadata. Bad params → `MetadataValidationError` (internal). Unlock path maps that → public `UNLOCK_FAILED`.

### Signature
```python
validate_kdf_parameters(
    memory_cost_kib: int,
    time_cost: int,
    parallelism: int,
    hash_len: int,
    salt: bytes,
) -> None
```

### Checks (all must pass)

| Param | Type | Bounds | Meaning |
|---|---|---|---|
| `memory_cost_kib` | `int` | 8192 … 1048576 KiB | RAM Argon2 uses |
| `time_cost` | `int` | 1 … 10 | iterations |
| `parallelism` | `int` | 1 … 16 | threads/lanes |
| `hash_len` | `int` | 16 … 64 | output key bytes |
| `salt` | `bytes` | len == 16 | KDF salt |

Fail if: wrong type, out of range, or salt not exactly 16 bytes.

### Defaults used on init
```
memory 65536 KiB (64 MiB)
time   3
parallelism 1
hash_len 32
salt   16 random bytes
```

### Why
- Stop DoS (huge memory/time from malicious metadata)
- Stop weak KDF (too-small memory/time/hash)
- Force fixed salt size
- Keep crypto path from running with garbage params

---

## `b64_encode` / `b64_decode`

**Where:** `src/crypto_utils.py`

Binary crypto bytes (salt, nonce, ciphertext) **not safe** as raw JSON text. Base64 turns bytes ↔ ASCII string for `vault_metadata.json`.

### Encode — bytes → string
```python
def b64_encode(data: bytes) -> str:
    # base64.b64encode → ASCII str
```
- Input must be `bytes` / `bytearray`
- Else → `MetadataValidationError`
- Used when **writing** metadata (`salt_b64`, `nonce_b64`, `ciphertext_and_tag_b64`)

### Decode — string → bytes
```python
def b64_decode(value: str) -> bytes:
    # base64.b64decode(..., validate=True)
```
- Input must be `str`
- `validate=True` → reject bad padding / non-base64 junk
- Fail → `MetadataValidationError`
- Used when **reading** metadata before KDF / AES-GCM

### Flow
```
init:  salt/nonce/ct bytes  → b64_encode → JSON on disk
unlock: JSON strings        → b64_decode → bytes for crypto
```

### Why not hex / raw
- Base64 compact, JSON-safe
- Strict decode blocks tampered / malformed metadata before crypto runs
