# Milestone 005: typed world-writable repair

Status: implemented 2026-09-14

`permissions.fixWorldWritable` replaces the control panel's root-privileged
`find ... -exec chmod o-w` pipeline with a typed engine mutation.

Security invariants:

- the requested root must exactly match a configured content root;
- traversal is fd-relative, stays on the starting filesystem, and never
  follows symbolic links;
- only already-opened regular files and directories are changed;
- the mutation removes only `S_IWOTH` and preserves every other mode bit;
- one host-wide permissions lock, idempotency replay, transaction state, and
  audit records cover the mutation.

The control panel has no raw SSH mutation fallback for this action.
