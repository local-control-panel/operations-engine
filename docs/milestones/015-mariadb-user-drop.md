# Milestone 015: MariaDB user removal

Status: implemented and advertised as `db.dropMariaDbUser`.

The operation removes one strictly validated MariaDB `user@host` account
through fixed Docker and `mariadb` argv. `root`, `mysql`, `mariadb.sys` and
`healthcheck` are denied case-insensitively in the engine contract.

The root password and generated SQL are delivered through stdin. Each account
has its own mutation lock, idempotency index, transaction state and append-only
audit log. The control panel's `maria_drop_user` command requires this
capability and has no legacy raw-SQL fallback.
