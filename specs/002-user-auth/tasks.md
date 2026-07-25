---

description: "Executable implementation tasks for Feature 0.2 user identity authentication"
---

# Tasks: User Identity Authentication

**Input**: Design documents from `/specs/002-user-auth/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/auth-service.md`, and `quickstart.md`

**Tests**: Required. The constitution and implementation plan require deterministic pytest coverage for every success path, failure path, and security boundary. Write each story's tests first and verify they fail before its implementation tasks.

**Organization**: Tasks are grouped by user story so every phase can be delivered and tested independently.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel with other marked tasks after their stated prerequisites, because they modify different files.
- **[Story]**: User story served by the task. Story labels appear only in user-story phases.
- Every task identifies its exact target file path.

## Path Conventions

- Application entry point: `main.py`
- Domain code: `src/`
- Tests: `tests/`
- Runtime account data: `data/users.json` (created at runtime; do not commit real accounts)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the Feature 0.2 package and test locations without changing Feature 0.1 behavior.

- [X] T001 Create the authentication package export boundary in `src/auth/__init__.py`
- [X] T002 [P] Create isolated authentication test fixtures for temporary user stores, deterministic clocks, token factories, and password hashers in `tests/conftest.py`
- [X] T003 [P] Add `data/users.json` and authentication-secret exclusion rules to `.gitignore`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Add the shared public failure vocabulary and safe mutable user-store primitive required by all authentication stories.

**⚠️ CRITICAL**: Complete this phase before starting any user-story implementation.

- [X] T004 Add stable `DUPLICATE_USER`, `INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`, and `UNAUTHENTICATED` codes plus non-sensitive domain error classes in `src/errors.py`
- [X] T005 Add strict schema-versioned user-store and account-record validation helpers in `src/storage/repository.py`
- [X] T006 Implement `UserRepository` read, create, and atomic replace operations with same-directory mode-restricted temporary files and file/directory `fsync` in `src/storage/repository.py`
- [X] T007 Add repository tests for absent-store behavior, schema validation, atomic account writes, no session storage, and safe malformed-store rejection in `tests/test_auth_repository.py`

**Checkpoint**: Stable errors and an isolated, validated `data/users.json` persistence boundary are ready for user-story work.

---

## Phase 3: User Story 1 - Register a Secure Account (Priority: P1) 🎯 MVP

**Goal**: Let a new user register one canonical email identity with a confirmed strong passphrase, retaining only an Argon2 verification representation.

**Independent Test**: Against an empty temporary user store, register valid credentials and verify one canonical account with a non-plaintext password representation is stored; duplicate, mismatched, weak, and malformed inputs create no account and return only stable outcomes.

### Tests for User Story 1

- [X] T008 [P] [US1] Add registration service tests for canonical email uniqueness, confirmation mismatch, strength-policy rejection, and secret-free persisted records in `tests/test_auth_service.py`
- [X] T009 [P] [US1] Add prompt-only registration CLI tests for success, stable failures, nonzero exits, and no passphrase echo in `tests/test_auth_cli.py`

### Implementation for User Story 1

- [X] T010 [US1] Implement canonical email validation and project passphrase-strength-policy reuse in `src/auth/service.py`
- [X] T011 [US1] Implement `AuthService.register` using Argon2 password hashing and `UserRepository` account creation in `src/auth/service.py`
- [X] T012 [US1] Add `register` parser command, email/passphrase/confirmation prompts, `registered` output, and stable error handling in `main.py`

**Checkpoint**: Registration is usable from the CLI and creates exactly one non-secret persistent account record per canonical email.

---

## Phase 4: User Story 2 - Log In and Use a Session (Priority: P1)

**Goal**: Authenticate an unlocked registered account and issue a fresh opaque credential that identifies that account for exactly 30 minutes in the current process only.

**Independent Test**: Register an account, log in successfully, validate the issued token as the canonical email before expiry, and confirm wrong credentials issue no token; advance an injected clock to expiry and reconstruct the service to confirm expired and restart-invalidated tokens are unauthenticated.

### Tests for User Story 2

- [X] T013 [P] [US2] Add login and session tests for correct and incorrect credentials, fresh opaque tokens, 30-minute expiry, expiry removal, and restart invalidation in `tests/test_auth_service.py`
- [X] T014 [P] [US2] Add login CLI tests for prompt-only credentials, exactly-one-token success output, and secret-free stable failure output in `tests/test_auth_cli.py`

### Implementation for User Story 2

- [X] T015 [US2] Implement Argon2 password verification and generic unknown-or-invalid credential handling in `src/auth/service.py`
- [X] T016 [US2] Implement injected clock/token-factory-backed in-memory session issuance and `validate_session` expiry removal in `src/auth/service.py`
- [X] T017 [US2] Add the `login` parser command, prompts, token-only success output, and stable authentication error handling in `main.py`

**Checkpoint**: Successful local login yields a unique usable process-local token; invalid, expired, and post-restart credentials consistently fail as unauthenticated.

---

## Phase 5: User Story 3 - Protect Accounts from Repeated Login Failures (Priority: P1)

**Goal**: Persist per-account consecutive login failures and enforce an exact five-minute lockout beginning with the fifth failed verification.

**Independent Test**: Register two accounts, submit five wrong passwords for one, verify the fifth returns `INVALID_CREDENTIALS` and records a five-minute lockout, verify all attempts during the interval return `ACCOUNT_LOCKED` without verification, then advance the injected clock and confirm correct login resets only that account's state.

### Tests for User Story 3

- [X] T018 [P] [US3] Add deterministic lockout tests for isolated per-account failure counts, fifth-failure persistence, active-lock verification skip, exact expiry, and successful-login reset in `tests/test_auth_service.py`
- [X] T019 [P] [US3] Add CLI lockout tests for `INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`, nonzero exits, and no token emission in `tests/test_auth_cli.py`

### Implementation for User Story 3

- [X] T020 [US3] Implement persisted failed-attempt increment and fifth-failure `locked_until = now + five minutes` transition in `src/auth/service.py`
- [X] T021 [US3] Implement active-lockout pre-verification rejection and expired-lock successful-login reset through `UserRepository` replacement in `src/auth/service.py`

**Checkpoint**: Lockout behavior is exact, account-scoped, restart-resilient, and cannot be bypassed using correct credentials during the five-minute interval.

---

## Phase 6: User Story 4 - Require Authentication Before Protected Access (Priority: P2)

**Goal**: Require a valid session at all KV and Transit public boundaries after the vault lock check and before ownership/downstream processing.

**Independent Test**: For representative KV and Transit calls, verify locked vaults return `VAULT_LOCKED` without validator/downstream calls; then with an unlocked vault, missing, invalid, and expired tokens return `UNAUTHENTICATED` before ownership/downstream calls, while valid validation supplies the canonical identity onward.

### Tests for User Story 4

- [X] T022 [P] [US4] Add KV gate-ordering tests for locked-first behavior, invalid-token rejection before downstream work, and identity propagation after validation in `tests/test_auth_kv_gate.py`
- [X] T023 [P] [US4] Add Transit gate-ordering tests for locked-first behavior, invalid-token rejection before downstream work, and identity propagation after validation in `tests/test_auth_transit_gate.py`

### Implementation for User Story 4

- [X] T024 [P] [US4] Inject an authentication validator, add `_require_authenticated`, and invoke it after `_require_unlocked` in every KV public operation in `src/kv/service.py`
- [X] T025 [P] [US4] Inject an authentication validator, add `_require_authenticated`, and invoke it after `_require_unlocked` in every Transit public operation in `src/transit/service.py`

**Checkpoint**: KV and Transit consistently preserve `VAULT_LOCKED` precedence and reject unauthenticated requests before authorization or protected processing.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Validate the finished feature, keep documentation accurate, and review required security constraints.

- [X] T026 [P] Document Feature 0.2 registration, login, session lifetime, and prompt-only CLI usage in `README.md`
- [X] T027 [P] Add manual validation and secret-handling notes for `data/users.json` to `specs/002-user-auth/quickstart.md`
- [X] T028 Run the complete pytest suite and resolve Feature 0.2 and Feature 0.1 regressions in `tests/`
- [X] T029 Inspect authentication code, CLI output, test fixtures, and account-store serialization for passphrase/hash/token leakage and record the review in `specs/002-user-auth/quickstart.md`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies.
- **Foundational (Phase 2)**: Depends on T001–T003 and blocks all user stories.
- **US1 (Phase 3)**: Depends on foundational errors and `UserRepository` (T004–T007).
- **US2 (Phase 4)**: Depends on completed US1 because it authenticates registered accounts.
- **US3 (Phase 5)**: Depends on completed US2 because it extends the login verification path and uses deterministic session/login seams.
- **US4 (Phase 6)**: Depends on completed US2 because KV/Transit consume `validate_session`; it does not depend on lockout behavior from US3.
- **Polish (Phase 7)**: Depends on every desired user-story phase.

### User Story Dependencies

- **US1 (P1)**: First independently deliverable increment after the foundation.
- **US2 (P1)**: Depends on US1 registration/account records.
- **US3 (P1)**: Depends on US2 login behavior; it is independently testable with its own account and clock fixtures.
- **US4 (P2)**: Depends on US2 session validation and may run in parallel with US3 after US2 completes.

### Within Each User Story

- Create and run the listed pytest tests first; confirm they fail before implementation.
- Complete implementation tasks in numerical order unless explicitly marked `[P]`.
- Run the phase's independent test criterion before moving to the next dependent story.

---

## Parallel Opportunities

- T002 and T003 can run in parallel after package setup begins.
- T008 and T009 can run in parallel because service and CLI tests are separate files.
- T013 and T014 can run in parallel because service and CLI tests are separate files.
- T018 and T019 can run in parallel because service and CLI tests are separate files.
- After US2, the US3 test/implementation stream and US4 test/implementation stream can proceed concurrently.
- T022/T024 and T023/T025 target separate KV and Transit modules and can run in parallel once the authentication contract is stable.
- T026 and T027 can run in parallel after implementation stabilizes.

## Parallel Example: User Story 4

```text
Task: "T022 [P] [US4] Add KV gate-ordering tests in tests/test_auth_kv_gate.py"
Task: "T023 [P] [US4] Add Transit gate-ordering tests in tests/test_auth_transit_gate.py"

Task: "T024 [P] [US4] Integrate authentication validation in src/kv/service.py"
Task: "T025 [P] [US4] Integrate authentication validation in src/transit/service.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete setup and the foundational error/store tasks.
2. Complete US1 tests, `AuthService.register`, and the `register` CLI flow.
3. Run `pytest tests/test_auth_repository.py tests/test_auth_service.py tests/test_auth_cli.py`.
4. Demonstrate registration with a temporary store and inspect it only for the required non-secret fields.

### Incremental Delivery

1. Deliver US1 secure registration and duplicate-safe account persistence.
2. Add US2 authentication and expiring process-local session validation.
3. Add US3 persistent five-failure lockout and reset behavior.
4. Add US4 KV/Transit session gates while preserving vault-lock precedence.
5. Run full `pytest`, manual prompt-only CLI validation, and the final leakage review.

### Security Constraints

- Never persist, log, print, commit, or include plaintext passphrases, Argon2 password hashes, or bearer tokens in errors.
- Do not accept passphrases as CLI command-line arguments.
- Keep sessions strictly in memory; `data/users.json` contains account and lockout state only.
- Preserve ordering: `VAULT_LOCKED` check, session validation, ownership authorization, then downstream work.