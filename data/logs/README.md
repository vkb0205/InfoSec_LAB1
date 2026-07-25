# Logs

Access-denied events and other audit logs should be stored here.

Runtime authorization denials are appended to:

```text
access_denied.jsonl
```

Each line is one JSON object containing only the UTC timestamp, requester
email, operation, resource type, and denied path/key identifier. Session
tokens, plaintext secret data, encryption keys, and passphrases must never be
logged.
