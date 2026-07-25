# Feature Specification: User Identity Authentication

**Feature Branch**: `002-user-auth`

**Created**: 2026-07-25

**Status**: Draft

**Input**: User description: "I want to build feature 0.2 in the Crypt_proj1.pdf file"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Register a Secure Account (Priority: P1)

As a new Mini Vault user, I register with my email address and a confirmed strong passphrase so the system can identify me without retaining my passphrase in readable form.

**Why this priority**: Registration establishes the user identity required before any authenticated access to secrets or named keys is possible.

**Independent Test**: From an empty user store, submit a valid email, strong passphrase, and matching confirmation; verify that registration succeeds, the account can later authenticate, and persisted user data contains no readable passphrase.

**Acceptance Scenarios**:

1. **Given** an email address not yet registered and a strong matching passphrase confirmation, **When** the user registers, **Then** the system creates one account and confirms registration without revealing passphrase material.
2. **Given** an email address already registered, **When** a user attempts to register it again, **Then** the system rejects the duplicate and does not change the existing account.
3. **Given** a passphrase and confirmation that do not match or a passphrase that does not meet the project strength policy, **When** the user registers, **Then** the system rejects registration and creates no account.

---

### User Story 2 - Log In and Use a Session (Priority: P1)

As a registered user, I log in with my email address and passphrase and receive a temporary session credential that identifies me for protected vault operations.

**Why this priority**: Authentication is required to distinguish the owner of each secret or named key before protected features can authorize access.

**Independent Test**: Register an account, log in with correct credentials, and use the issued session credential before its expiry; verify that it identifies the registered user. Attempt login with an incorrect passphrase and verify that no session is issued.

**Acceptance Scenarios**:

1. **Given** a registered account that is not locked, **When** the user supplies the correct email and passphrase, **Then** the system issues a new session credential valid for 30 minutes and resets that account's consecutive failed-login count.
2. **Given** a registered account, **When** the user supplies an incorrect passphrase, **Then** the system rejects the login, issues no session credential, and records one consecutive failed attempt.
3. **Given** a valid unexpired session credential, **When** a protected operation validates it, **Then** validation identifies the authenticated account for later authorization.
4. **Given** a session credential whose 30-minute validity period has elapsed, **When** it is presented to a protected operation, **Then** the operation rejects it as unauthenticated.

---

### User Story 3 - Protect Accounts from Repeated Login Failures (Priority: P1)

As a registered user, I expect my account to be temporarily protected from repeated incorrect login attempts while still becoming usable again after the required lockout period.

**Why this priority**: The assignment explicitly requires a temporary lockout after repeated failures, preventing password-guessing attempts against known accounts.

**Independent Test**: Register an account, submit five consecutive incorrect passphrases, verify that login is denied for exactly five minutes even with the correct passphrase, then verify that a correct login can succeed once the lockout has expired.

**Acceptance Scenarios**:

1. **Given** an unlocked registered account with fewer than five consecutive failed logins, **When** an incorrect passphrase is supplied, **Then** the system increments only that account's consecutive failed-login count and rejects the login.
2. **Given** an unlocked registered account, **When** its fifth consecutive incorrect passphrase is supplied, **Then** the system starts a five-minute account lockout and issues no session credential.
3. **Given** an account in its active five-minute lockout, **When** any login is attempted, including one with the correct passphrase, **Then** the system rejects the login and issues no session credential.
4. **Given** an account whose five-minute lockout has expired, **When** the correct passphrase is supplied, **Then** the system permits login and restores the account's normal authentication state.

---

### User Story 4 - Require Authentication Before Protected Access (Priority: P2)

As a vault user, I expect secret and named-key operations to reject unauthenticated requests before evaluating ownership or processing protected data.

**Why this priority**: This preserves a consistent security boundary for the KV and Transit features and prevents unauthenticated requests from reaching authorization or cryptographic work.

**Independent Test**: Invoke representative protected KV and Transit operations with no credential, an invalid credential, and an expired credential; verify that each is rejected as unauthenticated before ownership checks or protected-data processing occur.

**Acceptance Scenarios**:

1. **Given** an unlocked vault and no session credential, **When** a protected KV or Transit operation is requested, **Then** the operation rejects the request as unauthenticated before ownership evaluation.
2. **Given** an unlocked vault and an invalid or expired session credential, **When** a protected KV or Transit operation is requested, **Then** the operation rejects the request as unauthenticated before ownership evaluation.
3. **Given** a locked vault and any session credential state, **When** a protected KV or Transit operation is requested, **Then** the operation first reports that the vault is locked, preserving the Feature 0.1 gate.

### Edge Cases

- An email address is blank, malformed, or differs from an existing account only by case: registration is rejected or treated consistently under the project email-identity rule, without creating ambiguous identities.
- A registration request is interrupted or rejected after validation: no partial account or readable passphrase data is retained.
- A login is requested for an unregistered email: it is rejected without issuing a session or disclosing password-related internal details.
- A session credential is missing, empty, malformed, unknown, revoked by process restart, or expired: protected operations reject it as unauthenticated.
- Failed attempts for one account never lock, reset, or otherwise alter another account's login state.
- A successful login after prior failures resets the consecutive-failure count; only consecutive failures trigger lockout.
- Lockout expiry is evaluated using a reliable current time, and a login arriving before expiry remains denied.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST allow a user to register by providing an email address, passphrase, and matching passphrase confirmation.
- **FR-002**: The system MUST validate that a registration email is usable as an account identity and is unique according to one consistent email-identity rule.
- **FR-003**: The system MUST enforce the project's passphrase-strength policy at registration and reject a mismatched confirmation.
- **FR-004**: The system MUST retain passphrases only in a dedicated password-verification representation; it MUST NOT store, display, log, or return a plaintext passphrase or use unsalted general-purpose hashing alone as password protection.
- **FR-005**: The system MUST retain, per account, the email identity, password-verification representation, consecutive failed-login count, and lockout end time when applicable.
- **FR-006**: The system MUST authenticate login requests using the registered email and passphrase and issue a new opaque session credential only after successful authentication of an account that is not locked.
- **FR-007**: Each issued session credential MUST identify exactly one authenticated account, expire 30 minutes after issue, and become invalid after the process restarts unless the user logs in again.
- **FR-008**: The system MUST reject missing, malformed, unknown, or expired session credentials as unauthenticated and MUST NOT expose session credentials in logs, errors, or user listings.
- **FR-009**: The system MUST increment a registered account's consecutive failed-login count for each unsuccessful passphrase verification while the account is not locked, and MUST reset that count after a successful login.
- **FR-010**: On the fifth consecutive failed login for an account, the system MUST lock that account for exactly five minutes and issue no session credential.
- **FR-011**: While an account lockout is active, the system MUST reject every login attempt for that account, including attempts with the correct passphrase, without issuing a session credential.
- **FR-012**: Once a lockout has expired, the system MUST allow a correct login attempt to authenticate the account and restore normal failed-login state.
- **FR-013**: Every Feature 1 KV and Feature 2 Transit operation MUST require a valid unexpired session credential after the existing vault-unlocked check and before ownership authorization, storage access, or cryptographic processing.
- **FR-014**: Authentication failures, lockouts, and unauthenticated protected-operation attempts MUST return stable, non-sensitive outcomes that do not reveal passphrases, password-verification data, session credentials, or internal security details.

### Key Entities *(include if feature involves data)*

- **User Account**: The persistent identity record for one registered email, including its password-verification representation and login-protection state; it never contains a plaintext passphrase.
- **Session Credential**: A temporary bearer value issued after successful login that maps to one authenticated account and has a fixed expiry; it is not retained across process restarts.
- **Login Failure State**: Per-account security state that records the number of consecutive failed login attempts and, after the fifth failure, the time when the five-minute lockout ends.
- **Authenticated Identity**: The registered account identified by successful session validation and supplied to later ownership authorization.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In acceptance testing, 100% of valid first-time registration attempts create one usable account, while 100% of duplicate-email, mismatched-confirmation, and policy-failing passphrase attempts create no account.
- **SC-002**: Inspection of all persisted account records and authentication-related logs reveals 0 plaintext passphrases and 0 session credentials.
- **SC-003**: In 100 consecutive correct-login tests for an unlocked registered account, each login issues a usable session credential; each credential is rejected no later than 30 minutes after issue.
- **SC-004**: In 100 lockout test runs, the fifth consecutive incorrect login locks the tested account for exactly five minutes, and 100% of login attempts during that interval are rejected even when the correct passphrase is supplied.
- **SC-005**: In representative KV and Transit tests, 100% of calls with missing, invalid, or expired session credentials are rejected before ownership checks or protected-data processing.
- **SC-006**: A user with valid credentials can complete registration followed by login and receive a session credential in under two minutes under normal local operating conditions.

## Assumptions

- This specification implements assignment Feature 0.2, "User Identity Authentication," from `Crypt_proj1.pdf` and the corresponding grading criterion for password hashing, session tokens, and temporary lockout after five failed attempts.
- The existing vault-unlocked gate from Feature 0.1 remains in force and has precedence over session validation for protected operations.
- The project's established passphrase-strength policy is reused for account registration; if its exact thresholds are not yet defined, they will be documented during technical planning without weakening the requirement to validate strength.
- Email addresses are the sole user identity for this assignment; multi-factor authentication, password reset, email verification, account deletion, shared access policies, and persistent cross-restart sessions are outside this feature's scope.
- The five failed attempts must be consecutive for the same account. A successful login resets the count, and lockout ends automatically after five minutes.