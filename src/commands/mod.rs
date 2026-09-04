pub mod capabilities;
pub mod doctor;
pub mod engine;
pub mod ingress;
pub mod site;
pub mod version;

/// The single failure message every command emits when
/// `EngineConfig::load_root_owned` fails, for *any* reason — stale
/// `schemaVersion`, unparseable JSON, a config file not owned by root, or
/// one that is group/world-writable. Collapsing all four to one generic
/// `INTERNAL` message is deliberate: which of them it was is a property of
/// the host's private configuration, not something a remote caller is
/// entitled to learn.
///
/// **This exact text is a cross-repo contract, not an implementation
/// detail.** The `website-control-panel` client keys its engine-config
/// self-heal off this literal string: on seeing `INTERNAL` +
/// `"engine configuration is unavailable"` it rewrites the host's
/// `/etc/operations-engine/config.json` to the current schema and retries,
/// which is what turns a stale-schema config from an outage into a
/// self-repairing hiccup. Because the message is deliberately generic
/// there is no machine-readable discriminator behind it, so the string
/// *is* the interface.
///
/// Rewording it — even harmlessly, even to something clearer — silently
/// degrades that client back to the outage the self-heal was built to fix.
/// Nothing in this repo would fail. `commands::tests::
/// the_config_unavailable_message_is_a_pinned_cross_repo_contract` is what
/// fails instead, on purpose. If this text ever genuinely has to change,
/// the client's detection has to change first and ship first.
pub const CONFIG_UNAVAILABLE_MESSAGE: &str = "engine configuration is unavailable";

#[cfg(test)]
mod tests {
    use super::CONFIG_UNAVAILABLE_MESSAGE;

    /// Pins the literal, spelled out rather than compared to the constant,
    /// so editing the constant cannot silently edit its own test too.
    #[test]
    fn the_config_unavailable_message_is_a_pinned_cross_repo_contract() {
        assert_eq!(
            CONFIG_UNAVAILABLE_MESSAGE, "engine configuration is unavailable",
            "website-control-panel's engine-config self-heal matches this \
             exact string; changing it here degrades that client silently. \
             See CONFIG_UNAVAILABLE_MESSAGE's doc comment."
        );
    }
}
