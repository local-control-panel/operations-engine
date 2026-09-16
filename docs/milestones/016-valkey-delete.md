# Milestone 016: Valkey key deletion

Status: implemented and advertised as `db.deleteValkeyKey`.

The operation deletes one bounded Valkey key through fixed Docker and
`valkey-cli -x DEL` argv. The key is delivered verbatim through stdin, so
spaces, shell syntax, Unicode and control bytes never become command syntax.

Transaction scope uses only the key's SHA-256 digest. The raw key is absent
from argv, persisted state, result envelopes and audit records. Each key has
its own mutation lock, idempotency index and transaction history. The control
panel's `valkey_del` command requires this capability and has no legacy raw
shell fallback.
