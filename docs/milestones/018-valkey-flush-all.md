# Milestone 018: Valkey all-databases flush

Status: implemented and advertised as `db.flushAllValkey`.

The operation asynchronously flushes every logical database in one validated
Valkey container through fixed `valkey-cli FLUSHALL ASYNC` argv. Its typed
request must contain the exact `FLUSHALL` confirmation token; `FLUSHDB`, case
variants and whitespace variants fail before any subprocess runs.

Each container has a mutation lock, idempotency index, transaction state and
append-only audit log. The control panel's `valkey_flush_all` command requires
this capability and has no legacy raw-shell fallback.
