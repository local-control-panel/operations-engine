# Milestone 010: PostgreSQL database provisioning

Status: implemented and advertised as `db.provisionPostgres`.

The operation creates one strictly validated PostgreSQL database through a
fixed Docker and `psql` argv. The root password and generated SQL are delivered
through stdin, never through shell interpolation, process argv, protocol
diagnostics, transaction state, or audit records.

Each database has its own mutation lock, idempotency index, transaction state,
and append-only audit log. The control panel's `pg_create_db` command requires
this capability and has no legacy raw-SQL fallback.
