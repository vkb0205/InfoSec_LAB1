# Feature Specification: Vault Initialization and Unlock

**Feature Branch**: `001-init-unlock`

**Created**: 2026-07-23

**Status**: Draft

**Input**: User description: "I want to implement the feature 0.1"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Initialize Vault on First Run (Priority: P1)

As the person deploying Mini Vault, I set a strong Master Passphrase on the first run so the system can create and protect the vault's Data Encryption Key (DEK) before any protected service is used.

**Why this priority**: Initialization is the prerequisite for every later vault, KV, transit, and authentication flow that depends on an encrypted DEK.

**Independent Test**: Can be tested from a clean data directory by initializing with a valid Master Passphrase, then inspecting persisted metadata to confirm only encrypted DEK material and KDF metadata are stored.

**Acceptance Scenarios**:

1. **Given** no vault metadata exists, **When** the deployer initializes with a strong Master Passphrase, **Then** the system generates a random DEK, encrypts it under a key derived from the passphrase, and stores only encrypted DEK plus KDF metadata.
2. **Given** no vault metadata exists, **When** the deployer provides a weak Master Passphrase, **Then** initialization is rejected before DEK metadata is persisted.
3. **Given** vault metadata already exists, **When** initialization is requested again, **Then** the system refuses to overwrite or regenerate vault root material unless an explicit documented reset flow is used outside this feature.

---

### User Story 2 - Unlock Vault After Restart (Priority: P1)

As the person operating Mini Vault, I re-enter the Master Passphrase after every process restart so protected vault operations can decrypt required key material only in memory.

**Why this priority**: The assignment requires the vault to default to locked after every restart and to unlock only with the correct Master Passphrase.

**Independent Test**: Can be tested by initializing the vault, simulating a restart with persisted metadata, verifying locked state, then unlocking with the correct passphrase and confirming the DEK exists only in memory.

**Acceptance Scenarios**:

1. **Given** valid persisted vault metadata and a freshly started process, **When** no unlock has occurred, **Then** vault state is locked.
2. **Given** the vault is locked, **When** the correct Master Passphrase is supplied, **Then** the encrypted DEK is decrypted into process memory and the vault becomes unlocked.
3. **Given** the vault is locked, **When** an incorrect Master Passphrase is supplied, **Then** unlock fails with a generic error and vault state remains locked.

---

### User Story 3 - Block Protected Operations While Locked (Priority: P2)

As a user or service client, I receive a clear locked-vault error when attempting KV or Transit operations before the vault is unlocked.

**Why this priority**: Feature 0.1 establishes the locked/unlocked security boundary that Feature 1 and Feature 2 must respect.

**Independent Test**: Can be tested by starting from locked state and invoking representative KV and Transit operations; all must fail before session, authorization, encryption, decryption, signing, or storage logic proceeds.

**Acceptance Scenarios**:

1. **Given** the vault is locked, **When** a KV write, read, or delete is requested, **Then** the operation fails with `VAULT_LOCKED`.
2. **Given** the vault is locked, **When** Transit key creation, encryption, decryption, signing, or verification is requested, **Then** the operation fails with `VAULT_LOCKED`.

---

### Edge Cases

- Reusing the same Master Passphrase on two fresh initializations still produces different stored metadata because each initialization generates a fresh salt and fresh DEK.
- Corrupted, missing, malformed, or unsupported KDF metadata causes unlock to fail safely without exposing whether the salt, KDF parameters, ciphertext, nonce, tag, or passphrase was responsible.
- Failed unlock attempts never expose decrypted DEK bytes, partial key material, KDF internals, stack traces, or low-level cryptography error messages to the user.
- Process restart must clear unlocked state even if persisted metadata contains a `status` field.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST detect first-run state when no vault metadata exists and offer vault initialization.
- **FR-002**: System MUST require a strong Master Passphrase for initialization.
- **FR-003**: System MUST generate a fresh random salt for the Master Passphrase KDF during initialization.
- **FR-004**: System MUST derive an encryption key from the Master Passphrase using Argon2id or PBKDF2-HMAC-SHA256 with stored metadata sufficient for later unlock.
- **FR-005**: System MUST generate a fresh random Data Encryption Key (DEK) during initialization.
- **FR-006**: System MUST encrypt the DEK using AES-256-GCM or an approved AEAD construction before persistence.
- **FR-007**: System MUST persist only encrypted DEK material and non-secret KDF/encryption metadata; plaintext DEK and Master Passphrase MUST NOT be written to disk.
- **FR-008**: System MUST start in `locked` state after every process start or restart, regardless of prior successful unlocks.
- **FR-009**: System MUST decrypt the DEK into memory and transition to `unlocked` only when the correct Master Passphrase is supplied.
- **FR-010**: System MUST keep the vault locked and return a generic unlock failure when the Master Passphrase is wrong or metadata authentication fails.
- **FR-011**: System MUST make all Feature 1 KV and Feature 2 Transit operations fail with `VAULT_LOCKED` while locked, before authorization or cryptographic operations.
- **FR-012**: System MUST avoid logging, printing, returning, or storing the Master Passphrase, plaintext DEK, derived key, or decrypted key material.
- **FR-013**: System MUST reject repeat initialization when vault metadata already exists, unless a separate explicit reset procedure is implemented and documented outside this feature.

### Key Entities *(include if feature involves data)*

- **Vault Metadata**: Persisted non-secret initialization record containing KDF identifier, KDF salt, KDF parameters if applicable, encrypted DEK bytes, AEAD nonce/tag information if not bundled, and locked status metadata for display only.
- **Master Passphrase**: User-supplied secret used only to derive an unlock key; never persisted or logged.
- **Data Encryption Key (DEK)**: Random symmetric key generated at initialization; stored only encrypted at rest and held plaintext only in process memory while unlocked.
- **Vault State**: Runtime state indicating `locked` or `unlocked`; defaults to `locked` on every process start.

### Data Contract

```json
{
  "kdf": "argon2id",
  "kdf_salt_b64": "<salt>",
  "encrypted_dek_b64": "<encrypted DEK>",
  "status": "locked"
}
```

Implementations may add explicit KDF parameters and AEAD nonce/tag fields if the chosen ciphertext format does not bundle them, but MUST NOT add plaintext key material.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: From a clean data directory, vault initialization succeeds with a strong Master Passphrase and creates a metadata record matching the documented contract.
- **SC-002**: Inspection of all persisted vault metadata after initialization reveals no plaintext Master Passphrase, plaintext DEK, derived key bytes, or obvious secret fragments.
- **SC-003**: After a simulated restart, the vault reports or behaves as locked until the correct Master Passphrase is provided.
- **SC-004**: Unlock with the correct Master Passphrase succeeds and makes the in-memory DEK available to protected services without persisting plaintext key material.
- **SC-005**: Unlock with an incorrect Master Passphrase fails with one generic user-facing error and leaves the vault locked.
- **SC-006**: Representative KV and Transit calls attempted while locked fail deterministically with `VAULT_LOCKED`.

## Assumptions

- Feature 0.1 maps to `SPEC.md` section 5.1 and the grading rubric item "0.1 Init and Unlock".
- The project remains a local Python application using dependencies declared in `requirements.txt`.
- Persistent vault metadata is stored under approved project data paths and not outside the repository's documented data area.
- Authentication/session behavior from Feature 0.2 is out of scope except that later features must also pass the locked-vault gate.
- Strong passphrase policy details may follow the existing project helper or, if not yet implemented, should be documented in the implementation plan before coding.
