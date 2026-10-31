# Static publishing tests

The operations `site.publishStatic`, `site.staticStatus` and `site.recoverStatic`
are described in `protocol.md`. They fail closed unless the running ingress
container mounts `/var/lib/wcp-static` read-only at `/srv/wcp-static`.

Unit tests use a fake route backend and cover invalid plans, idempotent replay,
rejected artifacts preserving the previous release, route failure, interruption
checkpoints before and after the switch, and checkpoint cleanup after commit.
A failpoints-enabled subprocess test sends SIGKILL before and after the switch,
reopens persisted state, recovers explicitly and verifies the previous bytes.

A real Docker HTTP test uses a static-only Caddyfile:

```sh
WCP_STATIC_TEST_IMAGE=wcp-test-frankenphp:local \
WCP_STATIC_TEST_EXECUTABLE=frankenphp \
cargo test static_ingress::tests::docker_serves --lib -- --ignored
```

It checks HTML, assets, explicit SPA deep-link fallback, missing JS returning
404 and rejection of writes through the read-only publishing mount.
`WCP_STATIC_TEST_EXECUTABLE` defaults to `caddy`.

The host-level path (real ingress, route activation, probe, crash recovery) is
exercised by the panel's real-host workflow test.
