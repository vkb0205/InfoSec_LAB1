# Advanced Feature 2: MFA with TOTP

## 1. Goal

Add an optional Time-Based One-Time Password (TOTP) second factor to the
Feature 0.2 login flow. Accounts that do not enable MFA keep the current login
behavior. Accounts that enable MFA receive a session only after both their
passphrase and current TOTP code are valid.

The assignment names OTP/TOTP as an extra-credit feature but does not prescribe
an enrollment API, storage format, or recovery system. This specification uses
the smallest complete interoperable flow.

## 2. TOTP Profile

The implementation uses the common authenticator-app profile from RFC 6238:

- HMAC-SHA-1
- 30-second time step
- 6 decimal digits
- 20-byte random secret
- the current time step plus one adjacent step in either direction, allowing
  limited clock drift

The enrollment result includes a Base32 secret and an `otpauth://` provisioning
URI compatible with standard authenticator applications. No QR-code dependency
is needed.

## 3. Enrollment Flow

```text
enable_mfa(email, passphrase)
```

1. Canonicalize the email and load the account.
2. Enforce the existing five-attempt account lockout.
3. Reauthenticate with the account passphrase.
4. Reject an account that already has MFA enabled.
5. Generate a random TOTP seed.
6. Encrypt the seed before persistence.
7. Return the Base32 secret and provisioning URI once so the user can configure
   an authenticator application.

Enrollment uses direct passphrase reauthentication so it remains usable with
the project's process-local session model and CLI. A failed enrollment
passphrase is handled as a failed authentication attempt by the existing
lockout system.

There is no recovery-code, device-list, password-reset, or multi-device
workflow. The returned Base32 seed can be entered into more than one
authenticator during enrollment if desired.

## 4. Login Flow

The existing API gains one optional parameter:

```text
login(email, passphrase, otp=None) -> session_token
```

For an account without MFA:

```text
email + correct passphrase -> session token
```

For an account with MFA:

```text
email + correct passphrase + valid current TOTP -> session token
```

Missing, malformed, expired, or incorrect TOTP codes return the same
`INVALID_CREDENTIALS` result as a wrong passphrase and issue no session.
They increment the same per-account failed-attempt counter. The fifth
consecutive failed password or OTP attempt starts the existing five-minute
lockout. A complete successful login resets the counter.

Password verification occurs before TOTP seed decryption and verification.
This avoids performing TOTP work for an incorrect password.

## 5. TOTP Secret Protection

The TOTP seed is a long-term credential and must not be stored in plaintext.
It is encrypted with AES-256-GCM:

1. Generate a random 16-byte salt.
2. Derive a 32-byte wrapping key from the user's passphrase with the project's
   existing Argon2id KDF.
3. Generate a fresh 12-byte nonce.
4. Encrypt the raw 20-byte TOTP seed.
5. Bind the account email as AES-GCM associated data.
6. Store one Base64 envelope containing `salt || nonce || ciphertext || tag`.

The plaintext seed and derived key are not written to disk. Structurally invalid
account records fail strict repository validation. A valid-looking but tampered
encrypted seed causes a generic `INVALID_CREDENTIALS` login failure.

## 6. Account Data Contract

Legacy account records without an `mfa` field remain readable. New accounts
store `mfa: null` until enrollment:

```json
{
  "email": "alice@example.com",
  "password_hash": "<argon2 hash>",
  "failed_attempts": 0,
  "locked_until": null,
  "mfa": null
}
```

After enrollment:

```json
{
  "email": "alice@example.com",
  "password_hash": "<argon2 hash>",
  "failed_attempts": 0,
  "locked_until": null,
  "mfa": {
    "type": "TOTP",
    "encrypted_seed_b64": "<salt + nonce + ciphertext + tag>"
  }
}
```

The password hash, encrypted TOTP seed, and login lockout state remain in the
existing atomically replaced user store. Sessions remain process-local.

## 7. CLI Contract

```text
mini-vault enable-mfa
```

Prompts for email and passphrase, then prints the Base32 secret and provisioning
URI. Secrets are never accepted as command-line arguments.

```text
mini-vault login
```

Keeps the current email/passphrase prompts. It asks for a TOTP code only when
the identified account has MFA enabled, then prints a session token only after
both factors succeed.

## 8. Errors and Security Ordering

- Invalid caller input: `INVALID_INPUT`.
- Unknown account, wrong passphrase, or bad/missing TOTP:
  `INVALID_CREDENTIALS`.
- Active five-minute lockout: `ACCOUNT_LOCKED` before password or TOTP work.
- No token is generated or stored until every required factor succeeds.
- Errors and persisted data never expose the passphrase, plaintext seed, OTP,
  derived key, or session token.
- TOTP verification uses constant-time comparison for candidate codes.

## 9. Implementation Plan

1. Add a small standard-library TOTP helper with seed generation, code
   generation/verification, provisioning URI creation, and encrypted-seed
   wrapping.
2. Extend strict user-store validation with one optional `mfa` field while
   keeping legacy records compatible.
3. Add `enable_mfa`, `mfa_required`, and the optional `otp` login argument to
   `AuthService`.
4. Reuse one password-check helper and one failed-attempt helper so login and
   enrollment do not duplicate authentication policy.
5. Add the `enable-mfa` CLI command and conditional TOTP login prompt.
6. Test interoperability math, encrypted persistence, login enforcement,
   adjacent-step clock tolerance, lockout, tamper rejection, CLI behavior, and
   legacy account compatibility.

## 10. Acceptance Scenarios

1. A non-MFA account logs in exactly as before.
2. Enrollment returns a valid Base32 secret and `otpauth://` URI, while the user
   file contains neither the Base32 secret nor raw seed bytes.
3. An MFA account cannot log in with only the correct passphrase.
4. The correct passphrase and current TOTP issue a valid 30-minute session.
5. An expired or modified TOTP issues no session.
6. Five incorrect TOTP attempts trigger the existing exact five-minute
   lockout, including denial of a correct code during the lockout.
7. A code from one adjacent 30-second step is accepted for clock drift; a code
   outside that window is rejected.
8. Modifying the encrypted TOTP seed causes a generic authentication failure.
9. Restarting the service preserves MFA enrollment but invalidates old sessions,
   matching the existing session contract.
10. All existing authentication, KV, Transit, ACL, and versioning tests continue
    to pass unchanged.
