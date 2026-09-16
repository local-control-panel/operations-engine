# Milestone 020 — typed database export

Status: implemented and advertised as `db.export`.

MariaDB and PostgreSQL exports now use validated identifiers and fixed Docker
argv instead of panel-owned shell commands. The root-owned request keeps the
credential out of the `ops-engine` CLI argv, and output is bounded to 64 MiB
with a five-minute timeout.
