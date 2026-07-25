# Tasks: Feature 0.1 — Vault Initialization and Unlock

**Input**: Design documents from `LAB1/specs/001-init-unlock/`

**Prerequisites**: `plan.md` and `spec.md`

**Tests**: Required by `plan.md` precise tests and Mini Vault Constitution testing standards. Write tests first and verify they fail before implementation.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing. Paths are relative to the workspace root.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel because it uses a different file and has no dependency on another incomplete task in the same phase
- **[Story]**: User story label from `spec.md` (`US1`, `US2`, `US3`)
- Every task includes an exact file path

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Verify the Python project skeleton and create shared test scaffolding for isolated vault metadata paths.

- [x] T001 Inspect dependency declarations for `argon2-cffi`, `cryptography`, and `pytest` in `LAB1/requirements.txt`
- [x] T002 [P] Preserve the import smoke test baseline in `LAB1/tests/test_skeleton.py`
- [x] T003 [P] Create reusable pytest helpers for temporary metadata repositories and valid passphrases in `LAB1/tests/conftest.py`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Establish shared public error contracts, crypto metadata primitives, and repository shape that all stories consume.

**⚠️ CRITICAL**: No user story implementation should begin until this phase is complete.

- [x] T004 Define base domain exception classes and stable public `code` behavior in `LAB1/src/errors.py`
- [x] T005 Add the missing `ALREADY_INITIALIZED` public error constant while preserving existing constants in `LAB1/src/errors.py`
- [x] T006 [P] Add protocol constants for schema version, metadata AAD, KDF bounds, and default metadata path in `LAB1/src/crypto_utils.py`
- [x] T007 [P] Implement strict base64 encode/decode helpers in `LAB1/src/crypto_utils.py`
- [x] T008 Implement Argon2id KDF parameter validation and key derivation helpers in `LAB1/src/crypto_utils.py`
- [x] T009 Implement AES-256-GCM DEK wrap and unwrap helpers using fixed metadata AAD in `LAB1/src/crypto_utils.py`
- [x] T010 Implement zero-secret metadata construction and schema validation helpers in `LAB1/src/crypto_utils.py`
- [x] T011 Implement metadata repository read, existence check, and test-injectable path constructor in `LAB1/src/storage/repository.py`
- [x] T012 Implement atomic create-only metadata publication with restrictive temporary-file permissions in `LAB1/src/storage/repository.py`
- [x] T013 Translate repository collision and filesystem failures into public domain errors at service boundaries in `LAB1/src/storage/repository.py`

**Checkpoint**: Public error codes, metadata schema helpers, and repository persistence primitives are ready for user stories.

---

## Phase 3: User Story 1 - Initialize Vault on First Run (Priority: P1) 🎯 MVP

**Goal**: From a clean data directory, accept a strong Master Passphrase, create a fresh DEK, persist only encrypted metadata, and leave the vault locked.

**Independent Test**: Initialize with a valid passphrase using a `tmp_path` metadata repository, inspect the JSON envelope, confirm no plaintext secret material is persisted, and verify the same instance remains locked.

### Tests for User Story 1 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation.**

- [x] T014 [P] [US1] Add initialization metadata contract tests for schema version, Argon2id fields, salt length, nonce length, ciphertext/tag length, and locked state in `LAB1/tests/test_vault_initialization.py`
- [x] T015 [P] [US1] Add no-plaintext-persistence tests for passphrase, DEK fields, and allowed JSON keys in `LAB1/tests/test_vault_initialization.py`
- [x] T016 [P] [US1] Add weak passphrase rejection tests that assert `INVALID_INPUT` and no metadata or temp residue in `LAB1/tests/test_vault_initialization.py`
- [x] T017 [P] [US1] Add create-only repeat initialization and publish-race tests asserting `ALREADY_INITIALIZED` and unchanged bytes in `LAB1/tests/test_repository_create_only.py`
- [x] T018 [P] [US1] Add fresh entropy tests comparing two isolated initializations with the same passphrase in `LAB1/tests/test_vault_initialization.py`
- [x] T019 [P] [US1] Add CLI init tests that mock `getpass.getpass`, reject passphrase arguments, and report that the vault remains locked in `LAB1/tests/test_cli_init_unlock.py`

### Implementation for User Story 1

- [x] T020 [US1] Implement strong Master Passphrase validation before DEK generation or persistence in `LAB1/src/crypto_utils.py`
- [x] T021 [US1] Implement `Vault.__init__`, `Vault.is_initialized`, `Vault.is_locked`, and locked default state from metadata existence in `LAB1/src/core/vault.py`
- [x] T022 [US1] Implement `Vault.initialize` to validate passphrase, generate 32-byte DEK and 16-byte salt, wrap DEK, persist metadata, clear local sensitive values, and remain locked in `LAB1/src/core/vault.py`
- [x] T023 [US1] Implement guarded DEK accessor that raises `VAULT_LOCKED` while locked and never prints or logs key material in `LAB1/src/core/vault.py`
- [x] T024 [US1] Implement `init` command parsing and secure `getpass.getpass` prompting in `LAB1/main.py`
- [x] T025 [US1] Map expected initialization domain failures to public error-code output and nonzero CLI exit without traceback in `LAB1/main.py`

**Checkpoint**: User Story 1 is fully functional and testable independently from a clean metadata path.

---

## Phase 4: User Story 2 - Unlock Vault After Restart (Priority: P1)

**Goal**: A fresh process starts locked when metadata exists, unlocks only with the correct Master Passphrase, stores the plaintext DEK only in memory, and reports generic unlock failure for all metadata or cryptographic failures.

**Independent Test**: Initialize once, construct a fresh `Vault` over the same repository, assert it is locked, unlock with the correct passphrase, verify a 32-byte in-memory DEK, and confirm metadata bytes do not change.

### Tests for User Story 2 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation.**

- [x] T026 [P] [US2] Add restart-state tests proving fresh `Vault` instances start locked and cannot retrieve a DEK in `LAB1/tests/test_vault_unlock.py`
- [x] T027 [P] [US2] Add correct unlock tests proving unlocked state, 32-byte guarded DEK availability, and unchanged metadata bytes in `LAB1/tests/test_vault_unlock.py`
- [x] T028 [P] [US2] Add generic unlock failure tests for wrong passphrase, malformed JSON, unknown schema, invalid base64, wrong nonce length, truncated ciphertext/tag, and ciphertext mutation in `LAB1/tests/test_vault_unlock_failures.py`
- [x] T029 [P] [US2] Add KDF bounds rejection tests for memory, time, parallelism, hash length, and salt size violations in `LAB1/tests/test_vault_kdf_bounds.py`
- [x] T030 [P] [US2] Add CLI status and unlock tests for `uninitialized`, `locked`, `unlocked`, successful unlock, and exact `UNLOCK_FAILED` output without traceback in `LAB1/tests/test_cli_init_unlock.py`

### Implementation for User Story 2

- [x] T031 [US2] Implement metadata read and validation integration for unlock-time failures in `LAB1/src/core/vault.py`
- [x] T032 [US2] Implement `Vault.unlock` to derive the wrapping key, unwrap the DEK, verify exact 32-byte length, assign the in-memory DEK only after success, and transition to unlocked in `LAB1/src/core/vault.py`
- [x] T033 [US2] Ensure every failed unlock clears in-memory DEK state, leaves the instance locked, and maps all metadata/KDF/GCM/tag failures to `UNLOCK_FAILED` in `LAB1/src/core/vault.py`
- [x] T034 [US2] Implement `status` and `unlock` command parsing with secure `getpass.getpass` prompting in `LAB1/main.py`
- [x] T035 [US2] Ensure CLI `status` emits only `uninitialized`, `locked`, or `unlocked`, and CLI `unlock` emits only public codes for expected failures in `LAB1/main.py`

**Checkpoint**: User Story 2 is fully functional and testable independently after metadata has been initialized.

---

## Phase 5: User Story 3 - Block Protected Operations While Locked (Priority: P2)

**Goal**: All future KV and Transit protected operations fail first with `VAULT_LOCKED` while the shared vault is locked, before session validation, authorization, storage, parsing, or cryptography.

**Independent Test**: Instantiate KV and Transit services with a locked vault plus stubs that would fail if downstream work is invoked; each listed operation raises `VAULT_LOCKED` and no stub is called.

### Tests for User Story 3 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation.**

- [x] T036 [P] [US3] Add locked KV gate ordering tests for `write`, `read`, and `delete` using downstream stubs in `LAB1/tests/test_locked_kv_gate.py`
- [x] T037 [P] [US3] Add locked Transit gate ordering tests for key management, encrypt/decrypt, signing, sign, and verify operations using downstream stubs in `LAB1/tests/test_locked_transit_gate.py`

### Implementation for User Story 3

- [x] T038 [US3] Add lightweight Vault dependency injection and first-operation locked guard to `write`, `read`, and `delete` in `LAB1/src/kv/service.py`
- [x] T039 [US3] Add lightweight Vault dependency injection and first-operation locked guard to `create_key`, `list_keys`, and `revoke_key` in `LAB1/src/transit/service.py`
- [x] T040 [US3] Add first-operation locked guard to Transit `encrypt` and `decrypt` before parsing, authorization, lookup, storage, or crypto in `LAB1/src/transit/service.py`
- [x] T041 [US3] Add first-operation locked guard to Transit `create_signing_key`, `sign`, and `verify` before parsing, authorization, lookup, storage, or crypto in `LAB1/src/transit/service.py`

**Checkpoint**: User Story 3 is fully functional and testable independently with locked vault stubs.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Verify security boundaries, CLI consistency, documentation, and full-suite readiness.

- [x] T042 [P] Review all exception messages and CLI outputs for passphrase, DEK, derived-key, filesystem-path, traceback, Argon2, base64, and cryptography leakage in `LAB1/src/`
- [x] T043 [P] Update run instructions for `init`, `status`, `unlock`, and pytest execution in `LAB1/README.md`
- [x] T044 [P] Document Feature 0.1 security decisions and operational behavior for the report in `LAB1/report/README.md`
- [x] T045 Add or update `.gitignore` rules to prevent committing generated vault metadata and temporary metadata files in `LAB1/.gitignore`
- [x] T046 Run the full pytest suite and fix any failing tests in `LAB1/tests/`
- [x] T047 Verify no generated production metadata is committed under `LAB1/data/`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies; can start immediately.
- **Foundational (Phase 2)**: Depends on Setup completion; blocks all user stories.
- **User Story 1 (Phase 3)**: Depends on Foundational; delivers the MVP initialization flow.
- **User Story 2 (Phase 4)**: Depends on Foundational and requires metadata that US1 can produce; implementation can be developed with fixtures but end-to-end validation needs US1.
- **User Story 3 (Phase 5)**: Depends on Foundational and the `Vault` locked-state API from US1; can be tested with locked vault stubs.
- **Polish (Phase 6)**: Depends on completion of desired user stories.

### User Story Dependencies

- **US1 (P1)**: No dependency on other user stories after Foundational.
- **US2 (P1)**: Uses persisted metadata created by US1 for end-to-end restart/unlock validation.
- **US3 (P2)**: Uses the locked-state contract from US1 and does not require unlock success from US2.

### Within Each User Story

- Tests must be written and fail before implementation tasks.
- Crypto helpers and repository primitives precede Vault integration.
- Vault service behavior precedes CLI integration.
- Locked gates must execute before future session, authorization, parsing, storage, and cryptography logic.

---

## Parallel Opportunities

- Setup tasks T002 and T003 can run in parallel.
- Foundational crypto constants/base64 work T006 and T007 can run in parallel with repository read-shape work T011 after error constants are defined.
- US1 test tasks T014 through T019 can be drafted in parallel because they target independent behavior assertions.
- US2 test tasks T026 through T030 can be drafted in parallel because they target separate failure and CLI areas.
- US3 test tasks T036 and T037 can be drafted in parallel because KV and Transit gates are in different modules.
- Polish documentation and security review tasks T042 through T044 can run in parallel after implementation stabilizes.

---

## Parallel Example: User Story 1

```bash
Task: "T014 [P] [US1] Add initialization metadata contract tests in LAB1/tests/test_vault_initialization.py"
Task: "T017 [P] [US1] Add create-only repeat initialization and publish-race tests in LAB1/tests/test_repository_create_only.py"
Task: "T019 [P] [US1] Add CLI init tests in LAB1/tests/test_cli_init_unlock.py"
```

## Parallel Example: User Story 2

```bash
Task: "T028 [P] [US2] Add generic unlock failure tests in LAB1/tests/test_vault_unlock_failures.py"
Task: "T029 [P] [US2] Add KDF bounds rejection tests in LAB1/tests/test_vault_kdf_bounds.py"
Task: "T030 [P] [US2] Add CLI status and unlock tests in LAB1/tests/test_cli_init_unlock.py"
```

## Parallel Example: User Story 3

```bash
Task: "T036 [P] [US3] Add locked KV gate ordering tests in LAB1/tests/test_locked_kv_gate.py"
Task: "T037 [P] [US3] Add locked Transit gate ordering tests in LAB1/tests/test_locked_transit_gate.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 Setup.
2. Complete Phase 2 Foundational tasks.
3. Complete Phase 3 User Story 1.
4. Stop and validate with `pytest LAB1/tests/test_vault_initialization.py LAB1/tests/test_repository_create_only.py LAB1/tests/test_cli_init_unlock.py`.
5. Demo clean initialization and confirm the resulting vault remains locked.

### Incremental Delivery

1. Deliver US1 initialization and create-only metadata publication.
2. Add US2 restart/unlock behavior and generic unlock failures without changing initialized metadata format.
3. Add US3 locked gates for KV and Transit entry points.
4. Run the full pytest suite from `LAB1/` and review secret-leakage paths.

### Team Strategy

1. One developer owns `LAB1/src/crypto_utils.py` and crypto/schema tests.
2. One developer owns `LAB1/src/storage/repository.py`, `LAB1/src/core/vault.py`, and vault tests.
3. One developer owns `LAB1/main.py`, `LAB1/src/kv/service.py`, `LAB1/src/transit/service.py`, CLI tests, and gate tests.

---

## Notes

- Do not implement user registration, sessions, KV persistence, or Transit cryptography in this feature.
- Do not persist runtime unlocked state; a fresh `Vault` must never start unlocked.
- Do not expose low-level JSON, base64, Argon2, filesystem, or cryptography errors to users.
- Do not include passphrases, plaintext DEK bytes, derived keys, or decrypted key material in logs, exceptions, CLI output, metadata, or test assertion messages.
- Commit after each task or logical group and keep generated production metadata out of version control.
