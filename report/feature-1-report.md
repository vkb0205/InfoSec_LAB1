# Mini Vault Feature 1 Report: Secure Storage (KV Engine)

> **Canonical full write-up:** [`report/report.md`](report.md) **§4** (Feature 1.1 and 1.2).  
> This file is a short pointer only — do not maintain a second long copy.

## Scope

- **In scope:** Feature 1.1 encrypted-at-rest KV + Feature 1.2 ownership ACL  
- **Out of scope:** Bonus KV versioning (later)

## Where to read

| Topic | Section in `report/report.md` |
|-------|-------------------------------|
| Why Feature 1 / link to Feature 0 | §4.1 |
| AES-256-GCM, DEK, nonce, write/read/delete | §4.2 |
| Path rule, authorize-before-crypto, denial log | §4.3 |
| End-to-end flow | §4.4 |
| Security decisions | §4.5 |
| Demo steps | §4.6 and §7 |
| Tests | §4.7 and §7.4 |

## Quick module map

| Module | Role |
|--------|------|
| `src/kv/crypto_utils.py` | AES-256-GCM encrypt/decrypt, fresh nonce, tag verify |
| `src/kv/kv_engine.py` | Path ownership, write/read/delete, access-denied log |
| `main.py` | CLI `kv *`, interactive menu, `_KVFileStorage` → `data/kv_store.json` |
| `src/core/vault.py` | `get_dek()` when unlocked |
| `src/auth/service.py` | Session token → email |

## One-line summary

Secrets sealed with vault DEK (AES-GCM); only `secret/<email>/...` owner may touch them; disk shows ciphertext only.
