use crate::process::CancellationToken;

/// Marks that cancellation was requested before the commit point was
/// reached. It carries no detail because the caller already knows why: it
/// asked `CancellationToken::cancel()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cancelled;

/// The pre-commit phase of a mutation: work here is still safely abortable,
/// so it may be checked against `cancellation` between steps and unwound on
/// request.
pub struct PreCommit {
    cancellation: CancellationToken,
}

/// The post-commit phase: the operation has done the one thing that makes it
/// visible (activation switch, state transition, etc.) and must now run to
/// completion. There is deliberately no cancellation check here — the type
/// itself is the enforcement: once you hold a `PostCommit`, there is no
/// method left to call that could abort.
pub struct PostCommit {
    _private: (),
}

impl PreCommit {
    pub fn new(cancellation: CancellationToken) -> Self {
        Self { cancellation }
    }

    /// Returns `Err(Cancelled)` if cancellation was requested. Call this
    /// between pre-commit steps (preflight, fetch, stage, validate) so an
    /// operation can stop while everything it has touched is still
    /// revertible or simply discardable.
    pub fn check(&self) -> Result<(), Cancelled> {
        if self.cancellation.is_cancelled() {
            Err(Cancelled)
        } else {
            Ok(())
        }
    }

    /// Crosses the commit point. This is the single explicit place in an
    /// operation's code where "we are about to do the irreversible thing"
    /// is stated. It cannot fail and cannot be undone by a later
    /// cancellation request — from here, the operation must run to
    /// completion and report what actually happened.
    pub fn commit(self) -> PostCommit {
        PostCommit { _private: () }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cancelled, PreCommit};
    use crate::process::CancellationToken;

    #[test]
    fn check_succeeds_while_uncancelled() {
        let pre_commit = PreCommit::new(CancellationToken::default());
        assert_eq!(pre_commit.check(), Ok(()));
    }

    #[test]
    fn check_reports_cancellation_requested_before_commit() {
        let cancellation = CancellationToken::default();
        let pre_commit = PreCommit::new(cancellation.clone());
        cancellation.cancel();
        assert_eq!(pre_commit.check(), Err(Cancelled));
    }

    #[test]
    fn commit_is_reachable_once_preflight_work_is_done() {
        let pre_commit = PreCommit::new(CancellationToken::default());
        pre_commit
            .check()
            .expect("uncancelled preflight should pass");
        let _post_commit = pre_commit.commit();
        // No further cancellation check exists on `PostCommit` — that is
        // enforced by the compiler, not by a runtime assertion here.
    }
}
