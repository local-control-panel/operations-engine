# Milestone 011: PostgreSQL database removal

Status: implemented and advertised as `db.dropPostgres`.

The operation removes one strictly validated, non-system PostgreSQL database
through fixed Docker and `psql` argv. `postgres`, `template0` and `template1`
are denied in the engine contract. PostgreSQL's `WITH (FORCE)` closes active
sessions as part of the drop, avoiding the reconnect race in separate
terminate and drop statements.

The root password and generated SQL are delivered through stdin. Each database
has its own mutation lock, idempotency index, transaction state and append-only
audit log. The control panel's `pg_drop_db` command requires this capability
and has no legacy raw-SQL fallback.
