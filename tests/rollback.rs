//! End-to-end tests for the assembled `site.rollback` pipeline
//! (`rollback::execute::execute`), run for real against a local Git
//! "remote" the same way `tests/deploy.rs` does — two real deploys create
//! two real retained releases, and rollback switches `current` back
//! between them. Covers the milestone's rollback-specific failure cases:
//! a missing release, a corrupted release, concurrent attempts on one
//! site, an interrupted attempt, and a repeated idempotent request.

use std::{process::Command, thread};

use operations_engine::{
    config::SiteManifest,
    deploy::{self, execute::DeployContext},
    filesystem::ManagedRoot,
    mutation::preflight,
    process::CancellationToken,
    rollback::{
        RollbackRequest,
        execute::{RollbackContext, RollbackError, execute},
    },
    site::{SiteId, TrustedRoot},
    transaction::IdempotencyKey,
};

const SITE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const CREDENTIAL_ID: &str = "00000000-0000-0000-0000-000000000001";

struct Remote {
    _dir: tempfile::TempDir,
    url: String,
    branch: String,
    /// The first commit's SHA. Deploying this one happens while it is
    /// still the branch tip (see `advance`), since `deploy::resolve`
    /// authorizes only the *current* tip of an allowed branch.
    first_commit: String,
}

fn git(dir: &std::path::Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .expect("git should run");
    assert!(status.success(), "git {args:?} should succeed");
}

fn head(dir: &std::path::Path) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse should run");
    String::from_utf8(output.stdout)
        .expect("HEAD SHA should be UTF-8")
        .trim()
        .to_owned()
}

/// A local "remote" with one commit on its default branch. Deploy a second
/// commit onto it later via `advance`, once the first has already been
/// deployed while it was still the tip — `deploy::resolve` only authorizes
/// a revision that is the branch's *current* tip, so both commits can never
/// be pre-created before either deploy.
fn local_remote() -> Remote {
    let dir = tempfile::tempdir().expect("remote directory should exist");
    git(dir.path(), &["init", "--quiet"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "--allow-empty",
            "--quiet",
            "-m",
            "first",
        ],
    );
    let first_commit = head(dir.path());

    let branch_output = Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["symbolic-ref", "--short", "HEAD"])
        .output()
        .expect("git symbolic-ref should run");
    let branch = String::from_utf8(branch_output.stdout)
        .expect("branch name should be UTF-8")
        .trim()
        .to_owned();
    let url = dir
        .path()
        .to_str()
        .expect("path should be UTF-8")
        .to_owned();

    Remote {
        _dir: dir,
        url,
        branch,
        first_commit,
    }
}

/// Advances `remote`'s branch tip with a new commit and returns its SHA.
fn advance(remote: &Remote) -> String {
    git(
        remote._dir.path(),
        &[
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "--allow-empty",
            "--quiet",
            "-m",
            "next",
        ],
    );
    head(remote._dir.path())
}

fn current_username() -> String {
    let whoami = Command::new("whoami").output().expect("whoami should run");
    String::from_utf8(whoami.stdout)
        .expect("username should be UTF-8")
        .trim()
        .to_owned()
}

fn manifest_json(remote: &Remote) -> String {
    format!(
        r#"{{
          "schemaVersion": 1,
          "siteId": "{SITE_ID}",
          "domain": "example.com",
          "contentRoot": "sites/{SITE_ID}/current",
          "siteUser": "{user}",
          "repository": {{
            "url": "{url}",
            "allowedBranches": ["{branch}"],
            "credentialId": "{CREDENTIAL_ID}"
          }}
        }}"#,
        user = current_username(),
        url = remote.url,
        branch = remote.branch,
    )
}

struct Harness {
    _content_dir: tempfile::TempDir,
    _state_dir: tempfile::TempDir,
    _credential_dir: tempfile::TempDir,
    content_root: TrustedRoot,
    credential_root: TrustedRoot,
    engine_state: ManagedRoot,
}

fn harness() -> Harness {
    let content_dir = tempfile::tempdir().expect("content root should exist");
    let state_dir = tempfile::tempdir().expect("state root should exist");
    let credential_dir = tempfile::tempdir().expect("credential root should exist");
    let content_root =
        TrustedRoot::parse(content_dir.path()).expect("content root should be valid");
    let credential_root =
        TrustedRoot::parse(credential_dir.path()).expect("credential root should be valid");
    let state_root = TrustedRoot::parse(state_dir.path()).expect("state root should be valid");
    let engine_state = ManagedRoot::open(&state_root).expect("state root should open");

    Harness {
        _content_dir: content_dir,
        _state_dir: state_dir,
        _credential_dir: credential_dir,
        content_root,
        credential_root,
        engine_state,
    }
}

impl Harness {
    fn deploy_context(&self) -> DeployContext<'_> {
        DeployContext {
            content_root: &self.content_root,
            credential_root: &self.credential_root,
            engine_state: &self.engine_state,
        }
    }

    fn rollback_context(&self) -> RollbackContext<'_> {
        RollbackContext {
            content_root: &self.content_root,
            engine_state: &self.engine_state,
        }
    }
}

fn site_id() -> SiteId {
    SiteId::parse(SITE_ID).expect("site id should be canonical")
}

/// Deploys `commit` with `request_id` and returns the resulting
/// `ReleaseId` (equal to `request_id` per `deploy::ReleaseId::from`).
fn deploy(harness: &Harness, manifest: &SiteManifest, commit: &str, request_id: &str) -> String {
    let request = deploy::DeployRequest::parse(SITE_ID, commit, request_id, None)
        .expect("deploy request should be valid");
    deploy::execute::execute(
        &harness.deploy_context(),
        manifest,
        &request,
        &CancellationToken::default(),
    )
    .expect("setup deploy should succeed");
    request_id.to_owned()
}

const DEPLOY_A: &str = "123e4567-e89b-12d3-a456-426614174000";
const DEPLOY_B: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
const ROLLBACK_1: &str = "00000000-0000-0000-0000-0000000000a1";
const ROLLBACK_2: &str = "00000000-0000-0000-0000-0000000000a2";

#[test]
fn a_successful_rollback_switches_current_back_and_reports_both_releases() {
    let remote = local_remote();
    let harness = harness();
    let manifest = SiteManifest::from_json_for_site(&manifest_json(&remote), site_id())
        .expect("manifest should be valid");
    deploy(&harness, &manifest, &remote.first_commit, DEPLOY_A);
    let commit_b = advance(&remote);
    deploy(&harness, &manifest, &commit_b, DEPLOY_B);

    let release_a = deploy::ReleaseId::parse(DEPLOY_A).expect("release id should parse");
    let request = RollbackRequest::parse(SITE_ID, DEPLOY_A, ROLLBACK_1, None)
        .expect("rollback request should be valid");

    let result = execute(
        &harness.rollback_context(),
        &manifest,
        &request,
        &CancellationToken::default(),
    )
    .expect("rollback should succeed");

    assert_eq!(result.release_id, release_a);
    assert_eq!(result.release_id.to_string(), DEPLOY_A);
    assert_eq!(
        result.previous_release_id.map(|id| id.to_string()),
        Some(DEPLOY_B.to_owned())
    );

    let current = harness
        ._content_dir
        .path()
        .join(format!("sites/{SITE_ID}/current"));
    let target = std::fs::read_link(&current).expect("current should be a symlink");
    assert_eq!(
        target,
        std::path::Path::new(&format!("releases/{DEPLOY_A}"))
    );

    // The release rolled back *from* remains on disk and is itself still a
    // valid rollback target — nothing about this rollback deleted it.
    assert!(
        harness
            ._content_dir
            .path()
            .join(format!("sites/{SITE_ID}/releases/{DEPLOY_B}"))
            .exists()
    );
    let rollback_forward = RollbackRequest::parse(SITE_ID, DEPLOY_B, ROLLBACK_2, None)
        .expect("forward rollback request should be valid");
    let forward_result = execute(
        &harness.rollback_context(),
        &manifest,
        &rollback_forward,
        &CancellationToken::default(),
    )
    .expect("rolling forward again should succeed");
    assert_eq!(forward_result.release_id.to_string(), DEPLOY_B);
    assert_eq!(
        forward_result.previous_release_id.map(|id| id.to_string()),
        Some(DEPLOY_A.to_owned())
    );
}

#[test]
fn rollback_to_a_missing_release_fails_without_activating_anything_and_frees_the_lock() {
    let remote = local_remote();
    let harness = harness();
    let manifest = SiteManifest::from_json_for_site(&manifest_json(&remote), site_id())
        .expect("manifest should be valid");
    deploy(&harness, &manifest, &remote.first_commit, DEPLOY_A);

    let missing_release = "00000000-0000-0000-0000-00000000dead";
    let request = RollbackRequest::parse(SITE_ID, missing_release, ROLLBACK_1, None)
        .expect("rollback request should be valid");

    let outcome = execute(
        &harness.rollback_context(),
        &manifest,
        &request,
        &CancellationToken::default(),
    );
    assert!(matches!(outcome, Err(RollbackError::NotFound(_))));

    let current = harness
        ._content_dir
        .path()
        .join(format!("sites/{SITE_ID}/current"));
    let target = std::fs::read_link(&current).expect("current should still point at the deploy");
    assert_eq!(
        target,
        std::path::Path::new(&format!("releases/{DEPLOY_A}")),
        "a rollback to a missing release must not change the active release"
    );

    // The lock must be free again for a following valid attempt.
    let retry = RollbackRequest::parse(SITE_ID, DEPLOY_A, ROLLBACK_2, None)
        .expect("retry request should be valid");
    execute(
        &harness.rollback_context(),
        &manifest,
        &retry,
        &CancellationToken::default(),
    )
    .expect("a fresh attempt after a rejected one should succeed");
}

#[test]
fn rollback_to_a_corrupted_release_fails_validation_without_activating_anything() {
    let remote = local_remote();
    let harness = harness();
    let manifest = SiteManifest::from_json_for_site(&manifest_json(&remote), site_id())
        .expect("manifest should be valid");
    deploy(&harness, &manifest, &remote.first_commit, DEPLOY_A);
    let commit_b = advance(&remote);
    deploy(&harness, &manifest, &commit_b, DEPLOY_B);

    // Corrupt the retained (non-active) release DEPLOY_A by leaving an
    // untracked file in its working tree — the same "dirty working tree"
    // shape `deploy::validate`'s own tests use.
    std::fs::write(
        harness
            ._content_dir
            .path()
            .join(format!("sites/{SITE_ID}/releases/{DEPLOY_A}/tampered")),
        "unexpected",
    )
    .expect("tampering write should succeed");

    let request = RollbackRequest::parse(SITE_ID, DEPLOY_A, ROLLBACK_1, None)
        .expect("rollback request should be valid");
    let outcome = execute(
        &harness.rollback_context(),
        &manifest,
        &request,
        &CancellationToken::default(),
    );
    assert!(matches!(outcome, Err(RollbackError::Validate(_))));

    let current = harness
        ._content_dir
        .path()
        .join(format!("sites/{SITE_ID}/current"));
    let target = std::fs::read_link(&current).expect("current should still point at DEPLOY_B");
    assert_eq!(
        target,
        std::path::Path::new(&format!("releases/{DEPLOY_B}")),
        "a rollback to a corrupted release must not change the active release"
    );
}

#[test]
fn concurrent_rollback_attempts_on_the_same_site_are_serialized_by_the_site_lock() {
    let remote = local_remote();
    let harness = harness();
    let manifest = SiteManifest::from_json_for_site(&manifest_json(&remote), site_id())
        .expect("manifest should be valid");
    deploy(&harness, &manifest, &remote.first_commit, DEPLOY_A);
    let commit_b = advance(&remote);
    deploy(&harness, &manifest, &commit_b, DEPLOY_B);

    // Hold the site lock directly (bypassing the full pipeline) exactly
    // like `mutation::preflight`'s own contention tests, so the second,
    // genuinely concurrent `execute()` call on another OS thread is
    // guaranteed to observe it held rather than racing to finish first.
    let site_state = preflight::open_site_state(&harness.engine_state, site_id())
        .expect("site state should open");
    let held_request_id =
        operations_engine::transaction::RequestId::parse(ROLLBACK_1).expect("uuid should parse");
    let admitted = preflight::run(
        &site_state,
        held_request_id,
        None,
        operations_engine::rollback::OPERATION,
    )
    .expect("holder preflight should admit");
    let preflight::Outcome::Proceed(held) = admitted else {
        panic!("fresh preflight must proceed, not replay")
    };

    let contended = thread::scope(|scope| {
        scope
            .spawn(|| {
                let request = RollbackRequest::parse(SITE_ID, DEPLOY_A, ROLLBACK_2, None)
                    .expect("rollback request should be valid");
                execute(
                    &harness.rollback_context(),
                    &manifest,
                    &request,
                    &CancellationToken::default(),
                )
            })
            .join()
            .expect("contending thread should not panic")
    });
    assert!(
        matches!(
            contended,
            Err(RollbackError::Preflight(preflight::Error::Lock(_)))
        ),
        "a concurrent rollback attempt must observe the site lock held, got {contended:?}"
    );

    drop(held);
    let request = RollbackRequest::parse(SITE_ID, DEPLOY_A, ROLLBACK_2, None)
        .expect("rollback request should be valid");
    execute(
        &harness.rollback_context(),
        &manifest,
        &request,
        &CancellationToken::default(),
    )
    .expect("rollback should succeed once the lock is free");
}

#[test]
fn an_interrupted_rollback_leaves_recoverable_state_and_a_same_key_retry_is_reported_as_a_conflict()
{
    let remote = local_remote();
    let harness = harness();
    let manifest = SiteManifest::from_json_for_site(&manifest_json(&remote), site_id())
        .expect("manifest should be valid");
    deploy(&harness, &manifest, &remote.first_commit, DEPLOY_A);
    let commit_b = advance(&remote);
    deploy(&harness, &manifest, &commit_b, DEPLOY_B);

    let key = IdempotencyKey::parse("rollback-2026-09-02-01").expect("key should be valid");
    let site_state = preflight::open_site_state(&harness.engine_state, site_id())
        .expect("site state should open");
    let crashed_request_id =
        operations_engine::transaction::RequestId::parse(ROLLBACK_1).expect("uuid should parse");

    let admitted = preflight::run(
        &site_state,
        crashed_request_id,
        Some(&key),
        operations_engine::rollback::OPERATION,
    )
    .expect("preflight should admit");
    let preflight::Outcome::Proceed(admitted) = admitted else {
        panic!("fresh preflight must proceed, not replay")
    };
    // Simulate a crash: the process exits before ever reaching eligibility,
    // validation, or activation — the lock is never released and the
    // transaction state never leaves `InProgress`.
    std::mem::forget(admitted.lock);
    let abandoned_state = admitted.state;
    assert_eq!(
        abandoned_state.status,
        operations_engine::transaction::state::TransactionStatus::InProgress,
        "the crashed attempt's own in-memory state must reflect it never finished"
    );

    let reloaded = operations_engine::transaction::state::load(
        &site_state,
        &operations_engine::site::SiteRelativePath::parse(format!(
            "transactions/{crashed_request_id}.json"
        ))
        .expect("path should be valid"),
    )
    .expect("the crashed attempt's state must still be on disk for inspection");
    assert_eq!(
        reloaded.status,
        operations_engine::transaction::state::TransactionStatus::InProgress,
        "an abandoned rollback must not silently appear finished"
    );

    // A retry with the same idempotency key must not silently proceed (that
    // would risk a second, uncoordinated switch) and must not lose the
    // original attempt's record either — it is reported as a conflict.
    let retry = RollbackRequest::parse(SITE_ID, DEPLOY_A, ROLLBACK_2, Some(key.as_str()))
        .expect("retry request should be valid");
    let outcome = execute(
        &harness.rollback_context(),
        &manifest,
        &retry,
        &CancellationToken::default(),
    );
    assert!(
        matches!(outcome, Err(RollbackError::ReplayInProgress)),
        "expected ReplayInProgress, got {outcome:?}"
    );

    // `current` was never touched by the crashed or retried attempt.
    let current = harness
        ._content_dir
        .path()
        .join(format!("sites/{SITE_ID}/current"));
    let target = std::fs::read_link(&current).expect("current should still point at DEPLOY_B");
    assert_eq!(
        target,
        std::path::Path::new(&format!("releases/{DEPLOY_B}"))
    );
}

#[test]
fn retrying_a_successful_rollback_with_the_same_idempotency_key_replays_the_original_result() {
    let remote = local_remote();
    let harness = harness();
    let manifest = SiteManifest::from_json_for_site(&manifest_json(&remote), site_id())
        .expect("manifest should be valid");
    deploy(&harness, &manifest, &remote.first_commit, DEPLOY_A);
    let commit_b = advance(&remote);
    deploy(&harness, &manifest, &commit_b, DEPLOY_B);

    let key = IdempotencyKey::parse("rollback-2026-09-02-02").expect("key should be valid");
    let first_request = RollbackRequest::parse(SITE_ID, DEPLOY_A, ROLLBACK_1, Some(key.as_str()))
        .expect("first rollback request should be valid");
    let first_result = execute(
        &harness.rollback_context(),
        &manifest,
        &first_request,
        &CancellationToken::default(),
    )
    .expect("first rollback should succeed");

    let retry_request = RollbackRequest::parse(SITE_ID, DEPLOY_A, ROLLBACK_2, Some(key.as_str()))
        .expect("retry rollback request should be valid");
    let retry_result = execute(
        &harness.rollback_context(),
        &manifest,
        &retry_request,
        &CancellationToken::default(),
    )
    .expect("replay should resolve to the original outcome");

    assert_eq!(retry_result.release_id, first_result.release_id);
    assert_eq!(
        retry_result.previous_release_id,
        first_result.previous_release_id
    );

    let current = harness
        ._content_dir
        .path()
        .join(format!("sites/{SITE_ID}/current"));
    let target = std::fs::read_link(&current).expect("current should still point at DEPLOY_A");
    assert_eq!(
        target,
        std::path::Path::new(&format!("releases/{DEPLOY_A}")),
        "a replayed retry must not perform a second switch"
    );
}
