# Advanced Feature 5: Tamper-Evident Audit Log

## 1. Goal

Add a small hash-chained audit log that makes unauthorized changes to logged
security events detectable.

The current project audits denied KV and Transit access, so this feature chains
those existing events. It does not add a large event framework, database,
remote log server, log encryption, or background process.

## 2. Compatibility

The required features already produce two legacy access-denial formats:

- the KV text log
- the Transit JSONL denial log

Those outputs remain unchanged because existing required-feature tests and
operators may consume them. Each denial is also appended to the shared
tamper-evident `data/logs/audit.jsonl` log.

Tests and deployments may inject another audit path so they do not write to the
project data directory.

## 3. Audit Entry Contract

Each line is one canonical JSON object:

```json
{
  "entry_hash": "<64 lowercase SHA-256 hex characters>",
  "event": "TRANSIT_PERMISSION_DENIED",
  "key_name": "payments",
  "previous_hash": "<previous entry hash or 64 zeroes>",
  "requester_email": "alice@example.com",
  "sequence": 1,
  "timestamp": "2026-07-31T02:30:00Z"
}
```

KV denial entries use the same chain fields with these event fields:

```json
{
  "event": "KV_PERMISSION_DENIED",
  "operation": "READ",
  "path": "secret/alice@example.com/notes",
  "requester_email": "bob@example.com",
  "owner_email": "alice@example.com"
}
```

No entry may contain a session token, plaintext secret, ciphertext, key
material, password, OTP, or Shamir share.

## 4. Hash Chain

The genesis `previous_hash` is 64 zeroes.

For every entry:

1. Copy the event fields.
2. Add the next consecutive `sequence`.
3. Add a UTC `timestamp`.
4. Add `previous_hash`.
5. Serialize those fields as UTF-8 JSON with sorted keys and compact
   separators.
6. Set `entry_hash` to the lowercase SHA-256 hex digest of those bytes.
7. Append the complete canonical object as one JSONL line.

Before appending, the existing chain is verified. A damaged chain is never
silently extended.

## 5. Verification

Verification reads the complete file from the genesis entry and checks:

- every line is valid JSON and an object
- required chain fields have exact types and valid formats
- sequence numbers are consecutive and begin at 1
- every `previous_hash` equals the preceding `entry_hash`
- every stored `entry_hash` equals a fresh hash of that entry's other fields

An empty or not-yet-created log is valid. Any malformed, edited, inserted,
removed-from-the-middle, or reordered record makes verification return
`False`. A strict read operation raises a stable internal
`AuditIntegrityError`.

As with a standard unkeyed local hash chain, an attacker who can rewrite the
entire file and recompute every hash, or remove only an unanchored suffix,
cannot be detected without a trusted external signer or checkpoint. Those
systems are outside this assignment's requested hash-chain feature.

## 6. Failure Behavior

- A permission denial must still return the existing public denial error.
- Failure to write the audit file must not reveal internal filesystem details
  or turn a denial into an authorization success.
- If an existing audit chain is invalid, append raises
  `AuditIntegrityError`; verification continues to report `False`.
- Audit failures never trigger protected cryptographic or storage work.

## 7. Minimal API

```text
AuditLog(path).append(event_fields) -> complete_entry
AuditLog(path).verify() -> bool
AuditLog(path).read_verified() -> list[complete_entry]
verify_audit_log(path) -> bool
```

`event_fields` must be a non-empty JSON object containing a non-empty `event`
string and must not overwrite the reserved chain fields.

## 8. Implementation Plan

1. Add one dependency-free `src/audit.py` module using `hashlib`, `json`,
   `datetime`, and `pathlib`.
2. Preserve legacy KV logging and mirror each KV denial into the audit chain.
3. Preserve legacy Transit logging and mirror each Transit denial into the
   audit chain.
4. Support an optional audit path in both engines for isolated tests.
5. Test valid chaining, restart continuation, event integration, malformed
   records, field tampering, deletion, insertion, reordering, secret
   exclusion, and refusal to append to a damaged chain.
6. Run all existing tests to prove required features remain unchanged.

## 9. Acceptance Scenarios

1. The first event has sequence 1 and the zero genesis hash.
2. Each later event references the exact preceding entry hash.
3. A restarted `AuditLog` continues the existing chain.
4. Untouched logs verify successfully.
5. Editing any hashed event or chain field is detected.
6. Removing an entry from the middle is detected.
7. Inserting or reordering entries is detected.
8. Invalid JSON or an incomplete line is detected without an unhandled
   parsing error.
9. Appending to a damaged chain is refused and does not alter the file.
10. KV and Transit denials produce chained audit entries while their existing
    denial logs keep their original formats.
11. Audit records contain no supplied tokens, secrets, ciphertext, OTPs,
    passphrases, key material, or Shamir shares.
12. All required and previously implemented advanced-feature tests still pass.
