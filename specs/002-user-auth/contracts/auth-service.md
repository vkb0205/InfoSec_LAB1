# Authentication Service Contract

## Scope

Internal public contract for the Feature 0.2 CLI and protected-service boundaries. This is a Python domain-service contract, not a network API. Callers receive only stable public error codes and must not inspect secret internals.

## Operations

### `register(email, passphrase, confirmation) -> None`

Creates one new account.

| Input | Requirement |
|---|---|
| `email` | Usable account email normalized through one canonical identity rule. |
| `passphrase` | Meets established project passphrase-strength policy. |
| `confirmation` | Exactly matches `passphrase`. |

**Success**: Account is stored with password-verification representation, `failed_attempts = 0`, and `locked_until = null`.

| Code | Condition |
|---|---|
| `INVALID_INPUT` | Invalid email, weak passphrase, mismatched confirmation, or invalid store input. |
| `DUPLICATE_USER` | Canonical email already exists. |

### `login(email, passphrase) -> session_token`

Authenticates one unlocked account and issues a fresh 30-minute session credential.

**Success**: Returns one opaque token and resets failed-attempt/lock state.

| Code | Condition |
|---|---|
| `INVALID_CREDENTIALS` | Unknown email, failed verification, or safely unusable account data. |
| `ACCOUNT_LOCKED` | Active lockout; password verification is skipped. |
| `INVALID_INPUT` | Missing/malformed caller input. |

The fifth consecutive incorrect verification returns `INVALID_CREDENTIALS`, starts the five-minute lockout, and issues no token.

### `validate_session(token) -> email`

Returns canonical authenticated email only while the token is known and before its 30-minute expiry.

**Failure**: `UNAUTHENTICATED` for missing, malformed, unknown, expired, or restart-invalidated credentials. Expired credentials are removed during validation.

## Protected-Service Integration Contract

For every externally callable KV/Transit operation:

1. Check vault state. If locked, return `VAULT_LOCKED`; do not validate token or invoke downstream work.
2. Validate supplied token. If invalid, return `UNAUTHENTICATED`; do not perform ownership/downstream work.
3. Supply authenticated email to later ownership authorization, then perform storage/cryptographic work.

## CLI Contract

| Command | Prompts | Success output | Failure output |
|---|---|---|---|
| `mini-vault register` | Email, passphrase, confirmation | `registered` | Stable code; nonzero exit |
| `mini-vault login` | Email, passphrase | Newly issued opaque token on one line | Stable code; nonzero exit |

Passphrases are never command arguments. Errors, help, and logs never echo passphrases, hashes, or tokens.