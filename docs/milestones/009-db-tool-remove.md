# Milestone 009: protected database tool removal

Status: implemented and advertised as `dbTool.remove`.

The operation removes phpMyAdmin or Adminer without exposing a partial ingress
state. It moves an existing protected route outside Caddy's import glob,
validates and reloads Caddy, then removes the engine-owned container using fixed
argv. If Docker removal fails, the route is restored and Caddy is reloaded.

The request is a root-owned JSON file with an allowlisted `tool` and optional
validated `domain`. Per-tool locking, idempotency, transaction state, and audit
records share the same lifecycle scope as `dbTool.converge`, preventing races
between converge and remove requests.
