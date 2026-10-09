//! Deterministic crash points for tests (milestone 088).
//!
//! Compiled to nothing unless the `failpoints` cargo feature is on. With it,
//! `WCP_FAILPOINT=<name>` makes the process SIGKILL itself when it reaches
//! `hit("<name>")`, which is what an OOM kill or a power cut looks like to the
//! recovery code. Release builds never have the feature.

#[inline]
pub fn hit(name: &str) {
    #[cfg(all(feature = "failpoints", unix))]
    if std::env::var("WCP_FAILPOINT").is_ok_and(|v| v == name) {
        // SAFETY: kill(2) on our own pid; no memory is touched.
        unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
    }
    #[cfg(not(all(feature = "failpoints", unix)))]
    let _ = name;
}
