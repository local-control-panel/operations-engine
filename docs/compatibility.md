# Compatibility matrix

Tracks which published `ops-engine` versions speak which protocol
version, and the minimum control-plane (`website-control-panel`) build
known to work with them. Update this table as part of cutting each
release (`docs/release.md`); it is documentation only — runtime
compatibility is enforced independently by the control plane's protocol
version negotiation (`MIN_PROTOCOL_VERSION`/`MAX_PROTOCOL_VERSION` in
`website-control-panel`'s `ops_engine::mod.rs`).

| Engine version | Protocol version | Notes |
| --- | --- | --- |
| 0.1.0 – (current) | 1 | Initial and only protocol version so far. |

## Minimum host platform

`release.yml` builds `x86_64-unknown-linux-gnu` on the `ubuntu-latest`
GitHub Actions runner and `aarch64-unknown-linux-gnu` natively on
`ubuntu-24.04-arm` - both currently Ubuntu 24.04 LTS, glibc 2.39. This is a
floor implied by the build environment, not an independently chosen or
tested minimum: `ARTIFACT_NOT_RUNNABLE` (see `docs/protocol.md`'s error
taxonomy) is the most likely real-world trigger on an older distribution
whose glibc predates what the binary was linked against - `engine install`'s
pre-activation smoke test catches this before activation, but does not
distinguish "wrong glibc" from any other reason the binary failed to start.
No older distribution has been tested against a real build; if a managed
fleet needs one, test it explicitly and record the result here rather than
assuming compatibility.
