# Milestone 017: Valkey database flush

Status: implemented and advertised as `db.flushValkeyDb`.

The operation asynchronously flushes the selected Valkey container's current
database through fixed `valkey-cli FLUSHDB ASYNC` argv. Its typed request must
contain the exact `FLUSHDB` confirmation token; variants and the broader
`FLUSHALL` token fail validation before any subprocess runs.

Each container has a mutation lock, idempotency index, transaction state and
append-only audit log. The control panel's `valkey_flush_db` command requires
this capability and has no legacy raw-shell fallback.
