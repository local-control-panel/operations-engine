# Milestone 008: protected database tool convergence

Status: shipped 2026-09-14

`dbTool.converge` owns install, start, and stop for phpMyAdmin and Adminer. It
uses pinned multi-architecture manifest digests and fixed container/network
policy, with strict typed input and argv-only Docker execution. Each tool has
its own lock, idempotency index, transaction state, and audit log. A failed
install removes the partially created container.

The control panel continues to generate Basic Auth hashes and activates the
protected route through the already typed `ingress.activateConfig` operation.
If route activation fails, its existing compensation cleanup removes the tool
container. Destructive route/container removal remains milestone 009.
