# Data Model: User Identity Authentication

## User Store Document

**Purpose**: Persistent local container for registered accounts.

| Field | Type | Rules |
|---|---|---|
| `schema_version` | integer | Required; initial value `1`; unsupported versions fail safely. |
| `users` | object keyed by canonical email | Required; each key maps to one User Account. |

The document is `data/users.json`. It contains no sessions, plaintext passphrases, encryption keys, or vault DEK material.

## User Account

| Field | Type | Rules |
|---|---|---|
| `email` | string | Required canonical email; equals its enclosing store key; blank/malformed values fail validation. |
| `password_hash` | string | Required dedicated password-verification representation; never plaintext, returned, or logged. |
| `failed_attempts` | integer | Required non-negative consecutive failed-verification count for an unlocked account. |
| `locked_until` | string or null | `null` when normal; otherwise UTC instant when the five-minute lockout ends. |

### Validation rules

- Registration requires a unique canonical usable email, a passphrase satisfying the established project policy, and an exact confirmation match.
- The password-verification representation must be nonempty and acceptable to the verification library; malformed stored data fails safely rather than authenticating.
- `failed_attempts` is a non-negative integer. The implementation must record lockout at failure five.
- Non-null `locked_until` is a timezone-aware UTC instant.

### Account state transitions

```text
Normal (failed_attempts = 0, locked_until = null)
  ├─ wrong passphrase → Failed 1..4
  ├─ fifth consecutive wrong passphrase → Locked (failed_attempts = 5, locked_until = now + 5 min)
  └─ correct passphrase → Normal (reset, issue session)

Failed 1..4
  ├─ wrong passphrase → next failed state
  └─ correct passphrase → Normal (reset, issue session)

Locked
  ├─ any login before locked_until → Locked (reject without verification)
  └─ correct login at/after locked_until → Normal (clear lock/count, issue session)
```

Unregistered-email login never creates or alters a User Account.

## Session Credential (Runtime Only)

| Field | Type | Rules |
|---|---|---|
| `token` | opaque string | Fresh cryptographically secure bearer credential; map key only; never persisted/logged. |
| `email` | string | Canonical email of exactly one authenticated account. |
| `issued_at` | UTC instant | Runtime issue timestamp. |
| `expires_at` | UTC instant | Exactly 30 minutes after issue. |

### Session state transitions

```text
Absent → Issued (successful login) → Valid (before expiry)
Valid → Expired (at/after expiry; reject and remove)
Any state → Absent (process restart)
```

Missing, malformed, unknown, expired, and post-restart credentials produce the same unauthenticated outcome.

## Relationships

- One **User Account** can have zero or more valid in-memory **Session Credentials**.
- Each **Session Credential** belongs to exactly one **User Account**.
- A validated session supplies **Authenticated Identity** to later KV/Transit ownership checks; Feature 0.2 does not implement ownership policy.