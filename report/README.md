# Report Assets

Place report source files, diagrams, screenshots, and final PDF in this directory.

Final report path required by SPEC.md:

```text
docs/report/Report_StudentID1_StudentID2_StudentID3.pdf
```

## Feature 0.1 — Vault Initialization and Unlock

Implemented behavior:

- The vault metadata file is created only on first initialization at `data/vault_metadata.json`.
- The Master Passphrase is never stored. It is accepted through `getpass.getpass` in CLI flows.
- Initialization validates a strong passphrase before generating or persisting root material.
- A fresh 32-byte DEK, 16-byte Argon2id salt, and 12-byte AES-GCM nonce are generated for every initialization.
- The DEK is wrapped with AES-256-GCM using a key derived by Argon2id.
- Persisted metadata contains only schema, KDF, AEAD, salt, nonce, and ciphertext/tag fields.
- Initialization uses create-only publication and refuses repeat initialization with `ALREADY_INITIALIZED`.
- A successful initialization leaves the current vault instance locked and does not retain the plaintext DEK.
- A fresh process or `Vault` instance always starts locked when metadata exists.
- Unlock derives the wrapping key, authenticates and decrypts the wrapped DEK, then stores the plaintext DEK only in memory.
- Wrong passphrases, malformed metadata, invalid KDF parameters, invalid base64, nonce/ciphertext/tag problems, and GCM authentication failures all map to the generic `UNLOCK_FAILED` public code.
- KV and Transit public service methods perform the vault locked check first and raise `VAULT_LOCKED` before downstream authorization, storage, parsing, or cryptography.

Security decisions:

- Runtime unlocked state is intentionally not persisted.
- Public errors expose stable codes only: `INVALID_INPUT`, `ALREADY_INITIALIZED`, `UNLOCK_FAILED`, and `VAULT_LOCKED`.
- Low-level filesystem, JSON, base64, Argon2, and cryptography exceptions are not printed by normal CLI paths.
- Generated production metadata and temporary metadata files are ignored by version control.

Verification:

```bash
pytest
```

Current Feature 0.1 suite covers initialization contracts, no-plaintext persistence, weak passphrase rejection, create-only publication, fresh entropy, restart locked state, correct unlock, generic unlock failures, KDF bounds, CLI behavior, and locked KV/Transit gates.

## Feature 2.1 — Transit Named Key Management

- `create_key` generates a fresh 32-byte AES-256 key after the vault-unlocked
  and session-validation gates.
- The named key is bound to its name, owner email, and
  `key_usage = "ENCRYPT_DECRYPT"`.
- AES-256-GCM wraps the key with the in-memory DEK. The stored base64 envelope
  is `nonce || ciphertext || tag`; the owner/name/usage metadata is authenticated
  as associated data.
- `list_keys` returns only the current owner's key names and usages.
- `revoke_key` permanently removes only the current owner's matching key.
- Duplicate names are rejected with `DUPLICATE_KEY` within one owner's
  namespace. Different owners may independently use the same name.
- Public service results never contain plaintext or base64-encoded raw key
  material.

## Feature 2.2 — Transit Encryption and Decryption

- `encrypt` strictly decodes the client's base64 plaintext and loads only the
  authenticated owner's named `ENCRYPT_DECRYPT` key.
- The service unwraps that key with the in-memory DEK, generates a fresh
  12-byte nonce, and encrypts with AES-256-GCM.
- The response is self-describing:
  `vault:<key_name>:<base64(nonce || ciphertext || tag)>`.
- `decrypt` parses and validates the envelope, loads the owner-scoped key,
  authenticates the ciphertext and key name, and returns canonical base64
  plaintext.
- Malformed or truncated envelopes, revoked or unknown keys, wrong key usage,
  and GCM authentication failures are rejected without returning plaintext or
  key material.

## Feature 2.3 — Transit Named-Key Access Control

- Session validation supplies the canonical requester email before key lookup.
- Encrypt and decrypt load keys only from that owner's namespace.
- Foreign, missing, and revoked keys produce the same `PERMISSION_DENIED`
  response, avoiding key-existence disclosure.
- Denial happens before DEK access, key unwrapping, or client-data
  encryption/decryption.
- Every denied attempt writes a JSON-lines record containing the event type,
  requester email, and denied key name to `data/logs/access_denied.jsonl`.
