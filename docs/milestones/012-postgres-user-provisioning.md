# Milestone 012: PostgreSQL user provisioning

Status: implemented and advertised as `db.provisionPostgresUser`.

The operation creates one strictly validated PostgreSQL login role and may
grant access to one validated database in the same transaction. The built-in
`postgres` role and PostgreSQL's reserved `pg_` role namespace are denied.

Both credentials and generated SQL are delivered through stdin. Per-role
locking, idempotency, transaction state and audit records cover the mutation.
The control panel's `pg_create_user` command requires this capability and has
no raw `psql` fallback.
