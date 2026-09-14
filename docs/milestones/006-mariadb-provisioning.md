# Milestone 006: typed MariaDB provisioning

Status: shipped 2026-09-14

`db.provisionMariaDb` replaces five credential-bearing raw SSH/SQL mutation
paths: `maria_create_db`, `maria_create_user`, and the shared WordPress helper
used by install, clone, and migrate.

The root-owned staged plan separates database creation from grants to existing
databases and supports strict `create` and idempotent `ensure` modes. The fixed
client command receives the root password and SQL over stdin, while the normal
lock, idempotency, transaction, and audit pipeline records the operation.
