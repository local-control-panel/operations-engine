# Milestone 019: Backup artifact deletion

Status: implemented and advertised as `backup.delete`.

The operation deletes one `.sql` or `.sql.gz` file beneath the fixed
`/root/db-backups` trusted root. Absolute paths outside that root, traversal,
non-SQL artifacts and directory targets are rejected. Deletion is performed
through an opened directory capability rather than `rm` or another subprocess.

The relative path is represented in lock/transaction state only by its SHA-256
digest. Missing files return an idempotent successful result. Both the control
panel's backup-list deletion and import-list deletion require this capability
and have no legacy raw-shell fallback.
