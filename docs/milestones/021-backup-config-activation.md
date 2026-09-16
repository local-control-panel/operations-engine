# Milestone 021 — atomic remote-backup activation

Status: in progress; request validation landed, runtime activation is not yet
advertised and the control panel remains on its existing deployment path.

The new `backup.activateConfig` contract groups `rclone.conf`, `backup.conf`,
`notify.conf`, the backup agent and the complete crontab into one bounded
request. The remaining implementation must stage all five artifacts, validate
JSON/agent syntax, atomically replace the live set, install the crontab last,
and restore every previous artifact if activation fails. Secrets must never be
included in argv, diagnostics, transaction state or audit records.
