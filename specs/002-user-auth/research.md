# Research: User Identity Authentication

## Decision 1: Argon2 password hashing

- **Decision**: Use the installed `argon2-cffi` password-hashing/verification interface for account passphrases.
- **Rationale**: The assignment permits Argon2/bcrypt and forbids plain SHA. `argon2-cffi` is declared already and provides a password-verification representation with salt and parameters managed by the library.
- **Alternatives considered**: `bcrypt` is acceptable but creates a second password-hashing path. Reusing the master-passphrase raw KDF is rejected because it produces key material and couples unrelated security domains.

## Decision 2: Dedicated JSON user store

- **Decision**: Store versioned account records in `data/users.json` through a separate `UserRepository` using atomic complete-document replacement.
- **Rationale**: JSON is allowed by the assignment, matches the small local scope, and separates mutable accounts from immutable vault metadata. Atomic replacement avoids exposing partial registration or lockout updates.
- **Alternatives considered**: SQLite is unnecessary complexity at the stated scale. Extending `MetadataRepository` conflicts with its immutable create-only vault-envelope semantics.

## Decision 3: Opaque, process-local sessions

- **Decision**: Generate a fresh cryptographically secure opaque credential on successful login and retain token-to-email/expiry state only in memory.
- **Rationale**: This satisfies 30-minute expiry and restart invalidation without persisting bearer credentials. Validation is constant-time local work with no disk or password-hash operation.
- **Alternatives considered**: Persistent sessions increase bearer-secret and lifecycle risk. Signed self-contained tokens require a signing-key lifecycle and do not naturally enforce restart invalidation.

## Decision 4: Per-account lockout state

- **Decision**: Persist `failed_attempts` and optional `locked_until`; active lockout rejects before password verification; failure five records current time plus exactly five minutes; successful login resets state.
- **Rationale**: This exactly implements five consecutive failures and prevents correct-password bypass during lockout, while retaining protection across service reconstruction.
- **Alternatives considered**: Global counters affect unrelated accounts. Sliding-window rate limits differ from the required consecutive-failure rule. Memory-only counters disappear after restart.

## Decision 5: Preserve protected-operation order

- **Decision**: KV/Transit operations check vault state, then session validity, then future ownership/downstream work.
- **Rationale**: Feature 0.1 requires `VAULT_LOCKED` first; Feature 0.2 requires invalid sessions to fail before ownership or protected-data processing.
- **Alternatives considered**: Token-first behavior breaks Feature 0.1; downstream-only validation permits endpoint bypasses.

## Decision 6: Prompt-only CLI credentials

- **Decision**: Add `register` and `login` commands that prompt for secrets; never accept a passphrase as an argument. Successful login outputs its token for explicit later use.
- **Rationale**: Matches existing CLI behavior and avoids shell/process-list exposure of passphrases.
- **Alternatives considered**: Passphrase arguments are unsafe; a REST interface is optional and out of scope.