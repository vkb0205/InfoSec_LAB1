# Advanced Feature 3: Shamir's Secret Sharing

## 1. Goal

Add a Shamir unlock mode for Feature 0.1 in which no single Master Passphrase
can unlock the vault. Initialization creates `N` distinct key shares, and any
`K` valid shares from that set reconstruct the DEK-wrapping key.

The existing passphrase mode remains supported so current vault metadata,
tests, and deployments stay compatible. A newly initialized vault chooses
exactly one mode and cannot switch modes without an explicit reset/migration,
which is outside this feature.

## 2. Cryptographic Design

1. Generate the normal random 32-byte Data Encryption Key (DEK).
2. Generate a separate random 32-byte wrapping key.
3. Encrypt the DEK with the wrapping key using the existing AES-256-GCM
   metadata envelope and a fresh nonce.
4. Split the wrapping key into `N` Shamir shares with threshold `K`.
5. Persist only the encrypted DEK and non-secret Shamir configuration.
6. Return the `N` encoded shares once.
7. At unlock, reconstruct the wrapping key from at least `K` shares and use it
   to authenticate/decrypt the DEK.

The DEK itself is not placed directly into shares. This preserves the existing
DEK-wrapping boundary and means a failed reconstruction is rejected by the
AES-GCM authentication tag.

## 3. Shamir Parameters and Arithmetic

To keep the implementation small and auditable, each byte of the 32-byte
wrapping key is shared independently over the prime field `GF(257)`:

```text
f(x) = secret_byte + a1*x + ... + a(K-1)*x^(K-1) mod 257
```

- Each random coefficient is sampled uniformly from `0..256`.
- Share indexes use distinct nonzero values `1..N`.
- Each field value uses two bytes because it can be `256`.
- Lagrange interpolation at `x = 0` reconstructs each original byte.
- A reconstructed value of `256` is invalid because an original byte can only
  be `0..255`.

Parameter bounds:

```text
2 <= K <= N <= 255
```

This is a real threshold scheme: fewer than `K` shares reveal no information
about the random wrapping key.

## 4. Encoded Share Contract

Each share is URL-safe Base64 without padding and contains:

```text
magic | version | K | N | share_index | share_set_id | 32 field values
```

- `magic`: fixed Mini Vault share marker
- `version`: share format version
- `share_set_id`: fresh random 16-byte identifier generated per vault
- each of the 32 field values is encoded as an unsigned two-byte integer

The header allows early rejection of:

- malformed/noncanonical shares
- shares from a different vault
- mixed threshold/total configurations
- duplicate share indexes
- unsupported share versions

Share strings are bearer credentials. They are never stored in vault metadata,
logs, errors, or command history.

## 5. Shamir Metadata Contract

```json
{
  "schema_version": 1,
  "shamir": {
    "algorithm": "shamir-gf257",
    "threshold": 3,
    "total_shares": 5,
    "share_set_id_b64": "<16 random bytes>"
  },
  "aead": {
    "algorithm": "aes-256-gcm",
    "nonce_b64": "<12 random bytes>",
    "ciphertext_and_tag_b64": "<encrypted 32-byte DEK plus tag>"
  }
}
```

Passphrase metadata keeps the existing `kdf` object unchanged. Strict metadata
validation accepts one unlock descriptor—`kdf` or `shamir`—but never both.

The metadata stores no share, wrapping key, DEK, passphrase, or polynomial
coefficient.

## 6. Vault API

```text
initialize_shamir(threshold, total_shares) -> list[str]
unlock_with_shares(shares) -> None
shamir_config() -> {"threshold": K, "total_shares": N}
```

### Initialization

- Reject existing vault metadata before generating or returning shares.
- Reject booleans, non-integers, and values outside the parameter bounds.
- Return exactly `N` unique shares only after metadata is persisted.
- Leave the vault locked, matching passphrase initialization.

### Unlock

- Start and remain locked until the full operation succeeds.
- Require at least `K` structurally valid, unique shares.
- Validate every supplied share belongs to the metadata's share set.
- Sort shares by index and reconstruct from the first `K`; extra valid shares
  are accepted but not required.
- Any malformed, duplicate, mixed, insufficient, corrupted, or wrong-vault
  share set returns the same generic `UNLOCK_FAILED`.
- No partial key or share detail is disclosed.

Calling passphrase `unlock()` on a Shamir vault, or `unlock_with_shares()` on a
passphrase vault, also returns `UNLOCK_FAILED`.

## 7. CLI Contract

```text
mini-vault init-shamir
```

Prompts for `N` and `K`, initializes the vault, and prints the numbered shares
once followed by the normal locked status. Threshold and total are not secret,
but shares are never accepted as command-line arguments.

```text
mini-vault unlock-shamir
```

Reads the persisted threshold and securely prompts for exactly `K` shares with
hidden input. On success it prints `unlocked`; on every share/reconstruction
failure it prints `UNLOCK_FAILED`.

Existing `init` and `unlock` commands retain passphrase behavior.

## 8. Security and Failure Behavior

- `ALREADY_INITIALIZED`: any repeat initialization attempt.
- `INVALID_INPUT`: invalid `K/N` configuration.
- `UNLOCK_FAILED`: insufficient, malformed, duplicate, mixed, corrupted, or
  wrong-mode shares and all metadata/AEAD failures.
- `VAULT_LOCKED`: protected operations before successful reconstruction.
- The DEK and reconstructed wrapping key exist only in process memory.
- A process restart always discards them and starts locked.
- Shares are compared to metadata only through non-secret set/configuration
  identifiers; correctness is ultimately authenticated by AES-GCM.

## 9. Implementation Plan

1. Add one focused Shamir module for GF(257) split/combine and strict share
   encoding/decoding.
2. Extend vault metadata construction, validation, and extraction with the
   alternative `shamir` descriptor while leaving passphrase metadata unchanged.
3. Add `initialize_shamir`, `unlock_with_shares`, and `shamir_config` to
   `Vault`, reusing existing DEK generation and AEAD wrap/unwrap helpers.
4. Add explicit `init-shamir` and `unlock-shamir` CLI commands.
5. Test all K-of-N subsets, insufficient and duplicate shares, cross-vault
   mixing, share/metadata tampering, restart behavior, no persisted shares,
   wrong-mode calls, parameter bounds, and passphrase compatibility.

## 10. Acceptance Scenarios

1. A 3-of-5 vault returns five unique shares and remains locked.
2. Every combination of any three of those five shares unlocks the same DEK.
3. One or two shares never unlock the 3-of-5 vault.
4. Duplicate shares do not count more than once.
5. Shares from separately initialized vaults cannot be mixed.
6. Changing one encoded share byte causes generic unlock failure.
7. Changing threshold, total, share-set ID, nonce, ciphertext, or tag in
   metadata causes generic unlock failure.
8. Raw metadata contains none of the returned share strings or plaintext key
   material.
9. Restarting after a successful unlock returns to the locked state.
10. Existing Master Passphrase initialization/unlock and all later features
    continue to pass unchanged.
