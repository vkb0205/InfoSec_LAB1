# Implementation Plan: User Identity Authentication

**Branch**: `main` | **Date**: 2026-07-25 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/002-user-auth/spec.md`

## Summary

Implement assignment Feature 0.2: local user registration, secure password verification, temporary opaque sessions, and a five-consecutive-failure lockout lasting exactly five minutes. The existing Python CLI gains prompt-based registration and login. A new authentication service and user repository persist only account state, keep sessions in memory, and supply identity validation to KV and Transit after their existing locked-vault gate.

## Technical Context

**Language/Version**: Python 3.14 (current repository runtime)

**Primary Dependencies**: `argon2-cffi`; Python `secrets`, `datetime`, `json`, `os`, and `pathlib`; `pytest`

**Storage**: `data/users.json` for local account records; in-memory session map; existing `data/vault_metadata.json` unchanged

**Testing**: `pytest` with `tmp_path` plus injected repository, clock, token factory, and authentication validator

**Target Platform**: Local macOS/Linux/Windows command-line execution

**Project Type**: Local Python CLI application with domain services

**Performance Goals**: Registration and successful local login complete in under two minutes; session validation requires no disk read or password-hash operation

**Constraints**: Never persist, print, log, or include plaintext passphrases, password hashes, or bearer tokens in public errors; sessions last 30 minutes; fifth consecutive failure locks for exactly 5 minutes; operation order is vault lock, authentication, ownership, downstream work

**Scale/Scope**: One local process, tens to hundreds of accounts, process-local sessions; no password reset, MFA, email verification, multi-process session sharing, or account deletion

## Constitution Check

### Pre-design gate — PASS

| Constitution requirement | Plan response |
|---|---|
| Code quality and boundaries | Keep focused `auth`, `storage`, `kv`, and `transit` responsibilities; use explicit stable domain errors. |
| Secure by default | Use dedicated Argon2 password verification; opaque in-memory tokens; no secret logging or public leakage. |
| Testing standards | Add deterministic pytest coverage for every user story and gate-ordering test seams. |
| UX consistency | Add prompt-only CLI secrets and stable code output, consistent with Feature 0.1. |
| Resource discipline | Password verification only at login; in-memory session validation; atomic writes of the small local user store. |
| Persistent data | Store records only under `data/`; sessions are never persisted. |

No constitution violation or complexity exception is required.

## Project Structure

### Documentation (this feature)

```text
specs/002-user-auth/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── auth-service.md
└── tasks.md                 # Created later by /speckit-tasks
```

### Source Code (repository root)

```text
main.py                       # CLI commands and stable public output
src/
├── auth/service.py           # Registration, login, sessions, lockout
├── core/vault.py             # Existing locked-vault boundary
├── kv/service.py             # Vault gate then injected auth validation
├── transit/service.py        # Vault gate then injected auth validation
├── storage/repository.py     # Existing metadata + new user repository
└── errors.py                 # Stable authentication codes/classes
tests/
├── test_auth_service.py
├── test_auth_repository.py
├── test_auth_cli.py
├── test_auth_kv_gate.py
└── test_auth_transit_gate.py
data/users.json                # Runtime-created; never commit real accounts
```

**Structure Decision**: Retain the single CLI and current domain boundaries. Authentication owns registration/session policy; storage owns persistence; KV/Transit consume injected identity validation rather than duplicating token logic.

## Implementation Design

1. Add stable public codes/classes for duplicate registration, invalid credentials, active lockout, and unauthenticated token use. Preserve `VAULT_LOCKED` as the first protected-operation failure.
2. Add `UserRepository`, separate from create-only `MetadataRepository`, for a versioned `data/users.json` document. Strictly validate reads and atomically replace writes using a same-directory restricted temporary file, `fsync`, and replacement. Never store sessions or plaintext passphrases.
3. Implement `AuthService` with injected repository, clock, token factory, and password hasher. Normalize/validate email, reuse the project strength policy, hash/verify user passphrases through Argon2, and expose only stable non-sensitive failures.
4. Retain sessions only in an in-memory token-to-email/expiry map. Generate a fresh opaque token per successful login; reject/remove expired tokens; a new service starts without sessions.
5. Persist lockout state: failures increment only after failed verification for unlocked known accounts; failure five stores `locked_until = now + 5 minutes`; active lockout rejects before verification; successful login resets failure/lock state.
6. Extend KV/Transit with injected authentication validation. Every public operation calls `_require_unlocked()` then `_require_authenticated(token)` before current/future ownership and downstream work.
7. Add prompt-only `register` and `login` CLI commands. Registration prints `registered`; successful login prints the issued token only; all failures print a stable code without traceback.
8. Write tests first for repository behavior, registration, login/session expiry/restart invalidation, lockout timing/reset, CLI prompts, and KV/Transit ordering. Run `pytest` and inspect data/output for leakage.

## Post-design Constitution Check — PASS

The design keeps authentication in explicit domain services, uses a dedicated password-verification mechanism and memory-only sessions, provides deterministic test seams, and preserves locked-vault-first behavior. Persistence is limited to `data/users.json`; stable non-secret failure handling and security-boundary tests are mandatory. No gate is violated.

## Complexity Tracking

No constitution violations require justification.