# Person 1 Day 6 Test Matrix

This matrix maps the Person 1 tasks in `PLAN.md` to the minimum acceptance
tests in `SPEC.md` and `Crypt_proj1.md`.

| Requirement | Automated evidence | Status |
|---|---|---|
| Vault initialization stores only encrypted DEK | `test_vault_initialization_stores_only_encrypted_dek` inspects `vault.json`, checks its allowed fields, and searches for a known plaintext DEK and the master passphrase. | Pass |
| Vault restarts in locked state | `test_vault_restart_returns_to_locked_state` constructs a new `Vault` over initialized storage and requires `VAULT_LOCKED`. | Pass |
| Wrong Master Passphrase fails unlock | `test_wrong_master_passphrase_fails_unlock` requires the generic `UNLOCK_FAILED` response and a locked final state. | Pass |
| Feature 1 and Feature 2 fail while locked with `VAULT_LOCKED` | `test_feature_1_and_feature_2_fail_while_locked` sends valid-session KV and Transit request metadata through the shared `RequestGuard` after locking the vault. | Shared boundary passes; concrete endpoint binding pending Person 2/3 services |
| Registration stores only bcrypt or Argon2 password hash | `test_registration_persists_only_argon2id_password_hash` verifies the Argon2id hash and absence of the plaintext passphrase and plaintext password fields. | Pass |
| Successful login returns session token | `test_successful_login_returns_session_token` verifies the returned token and expiry, then proves only its SHA-256 fingerprint is stored. | Pass |
| Expired session token is rejected | `test_expired_session_token_is_rejected` advances to the exact 30-minute boundary, requires `UNAUTHENTICATED`, and verifies removal of the expired record. | Pass |
| Five consecutive failed logins lock the account for 5 minutes | `test_five_failed_logins_lock_account_for_exactly_five_minutes` checks attempts 1–4, the fifth attempt, correct-password rejection immediately before expiry, and successful login at the exact five-minute boundary. | Pass |

All methods above are in `tests/test_day6_person1_acceptance.py`. They use
reduced-cost Argon2id parameters only to keep automated tests fast; production
defaults in the application remain unchanged.

## Integration handoff

`src/kv/service.py` and `src/transit/service.py` currently contain package
descriptions but no callable feature services. Person 2 and Person 3 must route
every operation through the shared `RequestGuard`. When those operations are
available, add endpoint-level assertions for at least one KV operation and one
Transit operation while the vault is locked. The expected error code is
`VAULT_LOCKED`, even if the token is invalid or the target resource is not
owned by the requester.
