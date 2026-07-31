# Advanced Feature 4: Transit Key Rotation

## 1. Goal

Add versions to Transit `ENCRYPT_DECRYPT` named keys so an owner can rotate to
fresh AES-256 key material without losing the ability to decrypt ciphertext
created by older versions.

The feature is deliberately limited to symmetric encryption keys because the
assignment specifically requires old ciphertext decryption. Signing-key
rotation, automatic schedules, key-version deletion, and re-encryption jobs are
outside this feature.

## 2. Compatibility Strategy

Existing version-1 keys and ciphertext keep their current storage and API
formats. A key becomes a version-list record only when it is first rotated.

This preserves:

- existing persisted Transit keys
- all current version-1 ciphertext
- the current unrotated-key repository contract
- the current `list_keys()` response
- existing ACL policies, which remain attached to owner plus key name

No migration command or full-store rewrite is needed.

## 3. Rotation Flow

```text
rotate_key(token, key_name, key_owner_email=None)
```

1. Check the vault is unlocked.
2. Authenticate the session.
3. Resolve the owner namespace.
4. Require the caller to be the owner; ACL grants never authorize rotation.
5. Load the named key and require `key_usage = ENCRYPT_DECRYPT`.
6. Generate a new random 32-byte AES key.
7. Wrap it with the in-memory DEK using AES-256-GCM and a fresh nonce.
8. Append it as `latest_version + 1`.
9. Atomically replace the key record.
10. Return only the new version number, never key material.

For the first rotation, the current top-level
`encrypted_key_material_b64` becomes version 1 and the new material becomes
version 2.

## 4. Persistent Key Contracts

An unrotated key keeps the existing contract and is treated as version 1:

```json
{
  "key_name": "payments",
  "owner_email": "alice@example.com",
  "key_usage": "ENCRYPT_DECRYPT",
  "encrypted_key_material_b64": "<wrapped version 1>"
}
```

After rotation:

```json
{
  "key_name": "payments",
  "owner_email": "alice@example.com",
  "key_usage": "ENCRYPT_DECRYPT",
  "latest_version": 3,
  "versions": [
    {
      "version": 1,
      "encrypted_key_material_b64": "<wrapped version 1>"
    },
    {
      "version": 2,
      "encrypted_key_material_b64": "<wrapped version 2>"
    },
    {
      "version": 3,
      "encrypted_key_material_b64": "<wrapped version 3>"
    }
  ]
}
```

Repository validation requires:

- exact fields
- versions beginning at 1
- consecutive unique version numbers
- `latest_version` equal to the final version
- a structurally valid DEK-wrapped 32-byte envelope for every version

Signing-key storage remains unchanged.

## 5. Ciphertext Versions

Existing version-1 ciphertext remains:

```text
vault:<key-reference>:<base64(nonce + ciphertext + tag)>
```

After rotation, encryption uses only the newest key version and returns:

```text
vault:<key-reference>:v<version>:<base64(nonce + ciphertext + tag)>
```

Examples:

```text
vault:payments:v2:<payload>
vault:alice@example.com/payments:v3:<payload>
```

`decrypt()` parses the embedded version:

- unversioned ciphertext selects version 1
- `vN` ciphertext selects version N
- malformed, zero, negative, noncanonical, or unavailable versions return
  `INVALID_CIPHERTEXT`

Version 1 keeps the existing associated-data contracts. Version 2 and later
bind the key version into both the wrapped-key metadata and client-ciphertext
associated data. Changing the embedded version therefore cannot rebind a
ciphertext.

## 6. Management API

```text
rotate_key(token, key_name, key_owner_email=None)
    -> {"key_name", "key_usage", "latest_version"}

list_key_versions(token, key_name, key_owner_email=None)
    -> {"key_name", "latest_version", "versions"}
```

Both operations are owner-only. `list_key_versions` returns version numbers
only and never returns wrapped or plaintext material.

`list_keys()` remains unchanged for backward compatibility.

Revoking a named key still deletes the complete record, which permanently
removes every retained version. Individual historical versions cannot be
deleted because doing so would violate the stated old-ciphertext guarantee.

## 7. ACL Behavior

- ACLs remain attached to `(owner_email, key_name)`, not to individual versions.
- `ENCRYPT` permission always uses the latest version.
- `DECRYPT` permission allows the service to select the version embedded in the
  ciphertext.
- `SIGN` and `VERIFY` grants are unaffected.
- Only the owner may rotate or inspect the version list.
- Unauthorized rotation is denied before DEK access or key generation.

## 8. Errors and Security Ordering

- Locked vault: `VAULT_LOCKED` before authentication or repository access.
- Invalid/expired token: `UNAUTHENTICATED`.
- Non-owner rotation/version inspection: `PERMISSION_DENIED`.
- Signing key passed to rotation: `INVALID_KEY_USAGE`.
- Missing owner key: existing key-management `KEY_NOT_FOUND`.
- Malformed or unavailable ciphertext version: `INVALID_CIPHERTEXT`.
- Tampered key envelope or ciphertext/tag: existing generic decryption failure.

Rotation never returns, logs, or stores plaintext key material. A failed
repository update must not change the previously stored versions.

## 9. Implementation Plan

1. Extend strict Transit repository validation to accept legacy version-1
   records and consecutive version-list records.
2. Add atomic replacement of one existing named-key record.
3. Add owner-only `rotate_key` and `list_key_versions` service methods.
4. Make encryption select the latest version and emit `vN` after rotation.
5. Make decryption select version 1 for legacy ciphertext or the explicit
   version for new ciphertext.
6. Bind version 2+ into AES-GCM associated data while preserving version-1 AAD.
7. Test multi-rotation round trips, restart persistence, legacy compatibility,
   ACL behavior, owner-only management, revocation, malformed/tampered versions,
   storage validation, and locked/authentication ordering.

## 10. Acceptance Scenarios

1. An unrotated key still creates and decrypts the original ciphertext format.
2. Rotating version 1 creates version 2 with fresh wrapped key material.
3. New encryption after rotation embeds `v2` and uses version 2.
4. Ciphertext created before rotation still decrypts with version 1.
5. After several rotations, ciphertext from every retained version decrypts
   correctly after a service restart.
6. Changing `v3` to `v2` or modifying the payload causes decryption failure.
7. Missing or malformed version identifiers are rejected without unhandled
   exceptions.
8. A shared user with `ENCRYPT` uses the latest version and a user with
   `DECRYPT` can decrypt old and new ciphertext.
9. A shared non-owner cannot rotate the key even with both permissions.
10. Revoking the named key makes ciphertext from every version unusable.
11. No API or persisted record contains plaintext named-key material.
12. All existing Transit, ACL, MFA, Shamir, KV-versioning, and required-feature
    tests continue to pass unchanged.
