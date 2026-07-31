# Advanced Feature 6: Shared Signature Verification

## 1. Goal

Allow the owner of a Transit signing key to explicitly authorize another
authenticated user to call `verify()` with that key.

This extends section 2.4 without making verification anonymous or globally
public. Default deny remains in force: a non-owner needs an explicit
per-key `VERIFY` grant.

## 2. Reuse of the Existing Policy System

Advanced Feature 1 already provides the required persistent policy building
blocks:

- policies are scoped by `(owner_email, key_name)`
- grants are scoped to one canonical user email
- `VERIFY` is separate from `SIGN`
- owners manage grants
- vault and session checks precede policy evaluation
- verification authorization precedes key lookup and cryptographic work

This feature reuses that policy repository. It does not add another policy
file, duplicate public keys, copy key records, introduce roles or groups, or
make the key public.

## 3. Authorization Model

- The key owner has implicit `SIGN` and `VERIFY` access.
- A user explicitly granted `VERIFY` may verify signatures.
- A `VERIFY` grant does not grant `SIGN`.
- An authenticated user without the grant receives `PERMISSION_DENIED`.
- An unauthenticated or expired session receives `UNAUTHENTICATED` before
  policy lookup.
- Only the key owner may create or revoke a verification grant.
- Revoking the `VERIFY` grant immediately restores default deny.
- Revoking the named signing key removes its policy through the existing key
  revocation flow.

There is no wildcard `*` principal. "Any authenticated user" means any
authenticated account may be selected as an explicit grantee; it does not mean
all accounts automatically receive access.

## 4. Minimal Feature API

```text
grant_verify_access(
    token,
    key_name,
    verifier_email,
    key_owner_email=None,
)
    -> {
         "key_name",
         "owner_email",
         "grantee_email",
         "permissions": ["VERIFY"]
       }

revoke_verify_access(
    token,
    key_name,
    verifier_email,
    key_owner_email=None,
)
    -> {
         "key_name",
         "owner_email",
         "grantee_email",
         "permissions": <remaining key permissions>
       }
```

These are deliberately thin, verify-only adapters over the existing
`grant_key_access()` and `revoke_key_access()` APIs. The original general ACL
APIs remain compatible.

The existing verification call is reused:

```text
verify(
    token,
    key_name,
    message_b64,
    message_type,
    signature_b64,
    signing_algorithm=None,
    key_owner_email=None,
)
```

Because key names are unique only inside an owner's namespace, a grantee must
identify the owner using either:

- `key_owner_email="alice@example.com"`, or
- a qualified key reference such as `"alice@example.com/release-signer"`

## 5. Verification Flow

1. Require the vault to be unlocked.
2. Authenticate the caller's session.
3. Resolve the owner and key name.
4. Allow the owner, or require an exact `VERIFY` policy grant for the caller.
5. Load the signing-key record and require `SIGN_VERIFY` plus `ED25519`.
6. Validate the message mode and input.
7. Verify with `public_key_b64`.
8. Return the existing structured result:

```json
{
  "key_name": "release-signer",
  "signature_valid": true,
  "signing_algorithm": "ED25519"
}
```

Verification never decrypts `encrypted_private_key_b64` and therefore does not
access the vault DEK. The public key remains internal and is not returned.

## 6. Error and Privacy Behavior

- Locked vault: `VAULT_LOCKED`.
- Missing, invalid, or expired token: `UNAUTHENTICATED`.
- Non-owner grant management: `PERMISSION_DENIED`.
- Missing grant, revoked grant, foreign key, missing key, or revoked key:
  existing non-disclosing `PERMISSION_DENIED`.
- Encryption key used for verification: `INVALID_KEY_USAGE` after successful
  authorization.
- Wrong explicit signing algorithm: `INVALID_SIGNING_ALGORITHM`.
- Malformed or invalid signature: the existing structured
  `"signature_valid": false`.

Denied calls retain the existing access and tamper-evident audit events without
logging the token, message, signature, public key, or private key.

## 7. Implementation Plan

1. Add `grant_verify_access()` as a thin call to the existing grant API with
   exactly `["VERIFY"]`.
2. Add `revoke_verify_access()` as a thin call to the existing revoke API for
   exactly `["VERIFY"]`.
3. Keep the existing `verify()` authorization and cryptographic implementation;
   it already checks the operation-specific grant and uses only the public key.
4. Add tests for explicit grant, qualified references, default deny, verify-only
   permission, revocation, persistence across restart, owner-only policy
   management, authentication ordering, no DEK access, and no sensitive output.
5. Run the complete test suite to prove all required and advanced features
   remain compatible.

## 8. Acceptance Scenarios

1. A key owner signs and verifies exactly as before.
2. A non-owner without a grant cannot verify.
3. After an explicit grant, that authenticated user can verify a valid
   signature and receives the normal structured response.
4. The same grantee receives `signature_valid: false` for a modified message or
   wrong signature.
5. The grantee cannot sign merely because they can verify.
6. A second authenticated but ungranted user remains denied.
7. Revoking `VERIFY` immediately denies later verification.
8. A persisted grant still works after service restart.
9. Verification with a grant performs zero DEK accesses.
10. A non-owner cannot grant or revoke verification access.
11. Invalid authentication fails before repository, policy-dependent key use,
    or cryptography.
12. No response, policy, denial log, or audit entry exposes a token, message,
    signature, public key, private key, or decrypted key material.
