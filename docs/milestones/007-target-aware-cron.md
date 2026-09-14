# Milestone 007: target-aware cron convergence

Status: shipped 2026-09-14

`cron.installTab` now accepts an optional, strictly validated host user. Read,
hash-guard, install, locking, and transaction state all address that same user;
the username reaches `crontab` only as a separate argv value after `-u`.

This moves the control panel's `cron_add`, `cron_remove`, and `cron_toggle`
mutations off their raw SSH writer. Shared backup, deploy, and agent scheduling
also names the actual SSH account explicitly, avoiding ambiguity when the
engine itself is invoked through sudo.
