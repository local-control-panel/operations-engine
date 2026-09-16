# Milestone 014: MariaDB database removal

Status: implemented and advertised as `db.dropMariaDb`.

The operation removes one strictly validated, non-system MariaDB database
through fixed Docker and `mariadb` argv. `mysql`, `information_schema`,
`performance_schema` and `sys` are denied case-insensitively in the engine
contract.

The root password and generated SQL are delivered through stdin. Each database
has its own mutation lock, idempotency index, transaction state and append-only
audit log. The control panel's `maria_drop_db` command requires this capability
and has no legacy raw-SQL fallback.
