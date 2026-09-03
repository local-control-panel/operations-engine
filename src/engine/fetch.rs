//! The one place `engine::install`/`engine::rollback` reach the network:
//! a single HTTPS GET, response capped at `ureq`'s default 10 MiB limit
//! (`ops-engine` release binaries are a few MiB). No redirect target,
//! header, or response body content is ever trusted without the
//! checksum/signature checks in `verify.rs` — this module only fetches
//! bytes.
//!
//! Every request goes through one explicitly configured `ureq::Agent`
//! rather than `ureq`'s library defaults, which specify no timeouts at
//! all, discover a proxy from the ambient environment, and permit a
//! redirect to downgrade to plain HTTP. All three contradict rules this
//! project has written down: fetches happen while the engine-global lock
//! is held (`transaction::lock::DEFAULT_STALE_AFTER` is 15 minutes, so an
//! unbounded fetch can have its own lock stolen out from under it), and
//! the design spec's "no ambient discovery" rule excludes taking a
//! network destination from `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`.

use std::{sync::OnceLock, time::Duration};

/// Total wall-clock bound on one fetch, comfortably under
/// `transaction::lock::DEFAULT_STALE_AFTER` (15 minutes) so a stalled
/// download can never outlive the lock protecting the install it belongs
/// to. An install makes three of these calls in sequence.
const TIMEOUT_GLOBAL: Duration = Duration::from_secs(120);
const TIMEOUT_CONNECT: Duration = Duration::from_secs(15);
const TIMEOUT_RECV_BODY: Duration = Duration::from_secs(90);

#[derive(Debug)]
pub enum Error {
    /// The fetch exceeded one of this module's time bounds — reported as
    /// the stable `TIMEOUT` code rather than a generic fetch failure, so
    /// "GitHub is unreachable" is distinguishable from "GitHub said no".
    Timeout,
    Request(ureq::Error),
    Read(ureq::Error),
}

pub fn fetch_bytes(url: &str) -> Result<Vec<u8>, Error> {
    let mut response = agent(url)
        .get(url)
        .call()
        .map_err(|error| classify(error, Error::Request))?;
    response
        .body_mut()
        .read_to_vec()
        .map_err(|error| classify(error, Error::Read))
}

fn classify(error: ureq::Error, otherwise: fn(ureq::Error) -> Error) -> Error {
    if matches!(error, ureq::Error::Timeout(_)) {
        Error::Timeout
    } else {
        otherwise(error)
    }
}

/// The bounded agent every fetch uses. `https_only` is on for every real
/// destination, so a redirect away from the compiled-in
/// `https://github.com/...` release base can never downgrade to plain
/// HTTP. The one exception is a plain-HTTP loopback URL, which only
/// `tests/engine.rs`'s local fixture server ever uses (see
/// `install::InstallContext::release_base_url`); a production
/// `release_base_url` is a compiled-in constant that can never take that
/// branch.
fn agent(url: &str) -> &'static ureq::Agent {
    static HTTPS_ONLY: OnceLock<ureq::Agent> = OnceLock::new();
    static PLAIN_HTTP_LOOPBACK: OnceLock<ureq::Agent> = OnceLock::new();

    if is_plain_http_loopback(url) {
        PLAIN_HTTP_LOOPBACK.get_or_init(|| build_agent(false))
    } else {
        HTTPS_ONLY.get_or_init(|| build_agent(true))
    }
}

fn build_agent(https_only: bool) -> ureq::Agent {
    let config = ureq::config::Config::builder()
        .timeout_global(Some(TIMEOUT_GLOBAL))
        .timeout_connect(Some(TIMEOUT_CONNECT))
        .timeout_recv_body(Some(TIMEOUT_RECV_BODY))
        // `ureq`'s default is `Proxy::try_from_env()`. Routing a release
        // download through an environment-supplied host is exactly the
        // ambient discovery this design forbids.
        .proxy(None)
        .https_only(https_only)
        .build();
    ureq::Agent::new_with_config(config)
}

fn is_plain_http_loopback(url: &str) -> bool {
    let Some(authority) = url.strip_prefix("http://") else {
        return false;
    };
    let host_and_port = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    let host = host_and_port
        .rsplit_once(':')
        .map_or(host_and_port, |(host, _port)| host);
    matches!(host, "127.0.0.1" | "localhost" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::is_plain_http_loopback;

    #[test]
    fn only_plain_http_loopback_urls_are_exempt_from_https_only() {
        assert!(is_plain_http_loopback(
            "http://127.0.0.1:8080/v9.9.9/SHA256SUMS"
        ));
        assert!(is_plain_http_loopback("http://localhost:1/x"));
        assert!(is_plain_http_loopback("http://[::1]:1/x"));

        assert!(!is_plain_http_loopback(
            "https://github.com/skanevi/operations-engine/releases/download"
        ));
        assert!(!is_plain_http_loopback("http://example.test/v1/SHA256SUMS"));
        // A host that merely starts with the loopback address, or carries
        // it as userinfo, is not loopback.
        assert!(!is_plain_http_loopback("http://127.0.0.1.example.test/x"));
        assert!(!is_plain_http_loopback("http://127.0.0.1@example.test/x"));
    }
}
