# Milestone 004: typed ownership repair

Status: implemented 2026-09-13

`permissions.fixOwnership` replaces the control panel's root-privileged shell
pipeline (`find ... -exec chown`) with a typed, validated engine mutation.

Security invariants:

- the submitted plan is a root-owned, non-group/world-writable regular file;
- the fallback root must be an exact configured content root;
- site roots must be disjoint strict descendants of that root;
- traversal stays on the starting filesystem and never follows symlinks;
- ownership changes use numeric UID/GID and `AT_SYMLINK_NOFOLLOW`;
- one host-wide engine lock, idempotency replay, transaction state, and audit
  records cover the mutation.

The client may continue using read-only SSH discovery for runtime identity
files and the numeric `www-data` identity. Only the privileged mutation moved
behind the engine boundary.
