# Advanced Feature 1: Policy/ACL Sharing

## 1. Goal

Replace owner-only authorization with a small, explicit ACL layer so an owner can
share one KV secret or one Transit named key with selected authenticated users.
Existing owner behavior, encryption formats, KV versioning, and denial ordering
must remain compatible.

The assignment only names this feature; it does not prescribe an API or policy
schema. This specification therefore uses the smallest model that still provides
real per-resource, per-user, per-operation authorization.

## 2. Authorization Model

- Every resource keeps one immutable owner:
  - KV: the email in `secret/<owner_email>/...`
  - Transit: the `owner_email` stored with the named key
- The owner has implicit full access and is the only user allowed to manage the
  resource ACL or revoke/delete the resource itself.
- A policy contains explicit grants for individual user emails.
- A grant contains only allowed operations. There are no wildcard principals,
  groups, roles, inherited policies, or explicit deny rules.
- Default deny applies when no matching grant exists.
- ACL checks happen after vault/session checks and before key unwrapping or
  secret/key cryptographic operations.

Supported permissions:

| Resource | Permissions |
|---|---|
| KV secret | `READ`, `WRITE`, `DELETE` |
| Transit encryption key | `ENCRYPT`, `DECRYPT` |
| Transit signing key | `SIGN`, `VERIFY` |

Key creation, key revocation, ACL management, and ACL inspection remain
owner-only. A grantee with KV `DELETE` may delete the shared secret; deletion
also removes its ACL. Deleting/revoking any resource removes its ACL.

## 3. Persistent Policy Contract

Policies are stored separately from ciphertext and key material in
`data/policies.json`:

```json
{
  "schema_version": 1,
  "policies": [
    {
      "resource_type": "KV_SECRET",
      "owner_email": "alice@example.com",
      "resource_id": "secret/alice@example.com/database",
      "grants": {
        "bob@example.com": ["READ"]
      }
    },
    {
      "resource_type": "TRANSIT_KEY",
      "owner_email": "alice@example.com",
      "resource_id": "payments",
      "grants": {
        "bob@example.com": ["DECRYPT", "ENCRYPT"]
      }
    }
  ]
}
```

The repository validates the complete document, rejects unexpected fields or
permissions, prevents duplicate resource policies, and atomically replaces the
file. Malformed policy storage fails closed.

Policy metadata is not secret key material. It may expose the same owner,
resource path/key name, and user identity metadata already needed for access
control, but it never contains secret plaintext, named-key material, passwords,
session tokens, or ciphertext.

## 4. Public APIs

### KV Engine

The existing KV method order is retained.

```text
grant_access(path, grantee_email, permissions, token)
revoke_access(path, grantee_email, token, permissions=None)
get_acl(path, token)
list_shared(token)
```

- `permissions=None` on revoke removes every permission for that grantee.
- Passing permissions removes only those operations.
- Granting merges permissions with an existing grant.
- `get_acl` is owner-only and never returns secret data.
- `list_shared` returns resources and permissions shared with the caller.

Existing `read`, `write`, and `delete` allow either the owner or a grantee with
the matching permission. A grant can only be created for an existing secret.

### Transit Service

```text
grant_key_access(token, key_name, grantee_email, permissions,
                 key_owner_email=None)
revoke_key_access(token, key_name, grantee_email, permissions=None,
                  key_owner_email=None)
get_key_acl(token, key_name, key_owner_email=None)
list_shared_keys(token)
```

The optional `key_owner_email` also extends key-use operations:

```text
encrypt(token, key_name, plaintext_b64, key_owner_email=None)
decrypt(token, ciphertext, key_owner_email=None)
sign(..., key_owner_email=None)
verify(..., key_owner_email=None)
```

Owner-only calls omit `key_owner_email` and keep the current behavior. A shared
caller supplies the owner's email. Shared encryption returns a self-describing
identifier:

```text
vault:<owner_email>/<key_name>:<base64-envelope>
```

`decrypt` reads that qualified identifier automatically. For an older,
unqualified ciphertext, a shared caller can pass `key_owner_email`.

This explicit owner field is required because key names are unique only within
one owner's namespace.

## 5. Validation and Error Behavior

- Vault locked: `VAULT_LOCKED` before authentication or ACL work.
- Invalid/expired session: `UNAUTHENTICATED` before ACL evaluation.
- Invalid email, permission, resource type, or permission/key-usage
  combination: `INVALID_INPUT`.
- Non-owner ACL management and unauthorized resource use:
  `PERMISSION_DENIED`, logged without secret/key material.
- Missing and unauthorized Transit keys retain the same public denial behavior.
- Owners cannot grant themselves permissions because their access is already
  implicit.
- A grant validates and canonicalizes the grantee email but does not duplicate
  the authentication repository lookup. The grant is unusable unless a session
  later authenticates as that exact email.
- A grant does not expose or copy plaintext. Shared operations still use the
  server-side DEK and named key.

## 6. Implementation Plan

1. Add one strict, atomic `PolicyRepository` shared by KV and Transit.
2. Extend KV authorization to consult the policy after owner comparison.
3. Add owner-only KV ACL management and shared-resource discovery.
4. Extend Transit key resolution to use owner plus key name and check the
   operation-specific permission.
5. Add owner-only Transit ACL management, shared-key discovery, and ACL cleanup
   on resource deletion/revocation.
6. Add acceptance tests for permission granularity, default deny, revocation,
   persistence, authentication/lock ordering, and no cryptographic work on
   denial.

## 7. Acceptance Scenarios

1. Alice grants Bob `READ` on one secret; Bob can read it but cannot write or
   delete it.
2. Alice adds `WRITE`; Bob can create a new KV version without changing owner.
3. Alice revokes Bob; all later Bob operations are denied before decryption.
4. Bob cannot grant access to Alice's resource or inspect its full ACL.
5. Alice grants Bob `ENCRYPT` on an AES key; Bob can encrypt but cannot decrypt
   until `DECRYPT` is granted.
6. Alice and Bob may both own a key with the same name; an explicit owner
   selects the intended key.
7. `SIGN` and `VERIFY` grants are independently enforced for signing keys.
8. ACLs survive a service/repository restart and disappear when their resource
   is permanently deleted.
9. Existing owner-only tests and KV versioning continue to pass unchanged.
