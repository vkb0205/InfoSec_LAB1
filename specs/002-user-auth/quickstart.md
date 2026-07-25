# Quickstart: Validate User Identity Authentication

## Prerequisites

- Run from the repository root.
- Create an environment and install dependencies:

  ```bash
  python -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt
  ```

- Do not test against `data/users.json` containing real accounts. Pytest uses temporary paths.

See [data-model.md](data-model.md) for state and [contracts/auth-service.md](contracts/auth-service.md) for behavior.

## Automated validation

```bash
pytest
```

Expected: Feature 0.1 remains green; Feature 0.2 covers registration, secrecy, duplicates, login, expiry, restart invalidation, lockout, CLI behavior, and KV/Transit ordering.

## Manual CLI validation

1. Register:

   ```bash
   python main.py register
   ```

   Enter valid email and a strong passphrase twice. Expected: `registered`; no passphrase is printed.

2. Log in:

   ```bash
   python main.py login
   ```

   Enter matching credentials. Expected: one newly issued session token. Treat it as secret and do not log or commit it.

3. Submit an incorrect passphrase with `python main.py login`. Expected: `INVALID_CREDENTIALS`, nonzero exit, no token.

4. Repeat incorrect login until five consecutive failures. Expected: fifth failure starts lockout; all attempts, including correct credentials, return `ACCOUNT_LOCKED` for five minutes. Correct login succeeds at/after expiry and resets the count.

5. In a disposable demo only, inspect `data/users.json`. Expected: canonical email, password-verification representation, failure count, and lock time only—no plaintext passphrase or session token.

## Secret-handling review

- `data/users.json` is local runtime state and is ignored by Git. Do not copy, commit, or share it: Argon2 verification hashes are sensitive authentication material even though they are not plaintext passphrases.
- Passwords are accepted only through `getpass` prompts and are not command arguments, output, logs, or error details.
- Session tokens are process-local bearer credentials. Login prints one token for the caller to use, but application errors and account serialization never expose tokens.
- The account store has no `sessions` field; restart invalidates every previously issued token.

## Protected-boundary validation

Run KV and Transit ordering tests. Expected:

- Locked vault returns `VAULT_LOCKED` before token validation/downstream work.
- Unlocked vault with missing, invalid, or expired token returns `UNAUTHENTICATED` before ownership/downstream work.
- Validated token supplies identity to later ownership authorization without exposing the token.