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
