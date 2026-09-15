# Milestone 013: PostgreSQL user removal

Status: implemented and advertised as `db.dropPostgresUser`.

The operation removes one strictly validated non-system PostgreSQL role. The
`postgres` role and reserved `pg_` namespace are denied. The root credential
and fixed `DROP ROLE` SQL are delivered only through stdin.

The operation intentionally does not reassign ownership or cascade deletion:
roles with dependent objects fail closed. Per-role locking, idempotency,
transaction state and audit records cover the mutation. The control panel has
no raw `psql` fallback.
