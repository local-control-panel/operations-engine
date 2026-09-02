//! End-to-end tests for the assembled `site.deploy` pipeline
//! (`deploy::execute::execute`): preflight, resolve, stage, validate,
//! activate, and result/audit persistence, run for real against a local
//! Git "remote" (no network, no SSH — `git` accepts a plain filesystem
//! path). Mirrors the Phase 3 exit-criteria style of `tests/transaction.rs`
//! but for the actual Phase 4 operation those primitives were built for.

use std::process::Command;

use operations_engine::{
    config::SiteManifest,
    deploy::{
        DeployRequest,
        execute::{DeployContext, DeployError, execute},
    },
    filesystem::ManagedRoot,
    process::CancellationToken,
    site::{SiteId, TrustedRoot},
    transaction::IdempotencyKey,
};

const SITE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const CREDENTIAL_ID: &str = "00000000-0000-0000-0000-000000000001";

struct Remote {
    _dir: tempfile::TempDir,
    url: String,
    branch: String,
    head: String,
}

fn local_remote() -> Remote {
    let dir = tempfile::tempdir().expect("remote directory should exist");
    let run = |args: &[&str]| {
        let status = Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(args)
            .status()
            .expect("git should run");
        assert!(status.success(), "git {args:?} should succeed");
    };
    run(&["init", "--quiet"]);
    run(&[
        "-c",
        "user.name=test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "--allow-empty",
        "--quiet",
        "-m",
        "initial",
    ]);
    let branch = Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["symbolic-ref", "--short", "HEAD"])
        .output()
        .expect("git symbolic-ref should run");
    let branch = String::from_utf8(branch.stdout)
        .expect("branch name should be UTF-8")
        .trim()
        .to_owned();
    let head = Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse should run");
    let head = String::from_utf8(head.stdout)
        .expect("HEAD SHA should be UTF-8")
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
        head,
    }
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

fn site_id() -> SiteId {
    SiteId::parse(SITE_ID).expect("site id should be canonical")
}

#[test]
fn a_full_deploy_activates_the_release_and_records_success() {
    let remote = local_remote();
    let harness = harness();
    let manifest = SiteManifest::from_json_for_site(&manifest_json(&remote), site_id())
        .expect("manifest should be valid");
    let request_id = "123e4567-e89b-12d3-a456-426614174000";
    let request = DeployRequest::parse(SITE_ID, &remote.head, request_id, None)
        .expect("request should be valid");
    let context = DeployContext {
        content_root: &harness.content_root,
        credential_root: &harness.credential_root,
        engine_state: &harness.engine_state,
    };

    let result = execute(&context, &manifest, &request, &CancellationToken::default())
        .expect("deploy should succeed");

    assert_eq!(result.release_id.to_string(), request_id);
    assert_eq!(result.previous_release_id, None);
    assert_eq!(result.commit.as_str(), remote.head);

    let current = harness
        ._content_dir
        .path()
        .join(format!("sites/{SITE_ID}/current"));
    assert!(
        current.exists(),
        "current should resolve to the new release"
    );
    assert!(
        current.join(".git").exists(),
        "current should point at a real checkout"
    );
}

#[test]
fn retrying_with_the_same_idempotency_key_replays_the_original_result_without_redeploying() {
    let remote = local_remote();
    let harness = harness();
    let manifest = SiteManifest::from_json_for_site(&manifest_json(&remote), site_id())
        .expect("manifest should be valid");
    let key = IdempotencyKey::parse("deploy-2026-09-02-01").expect("key should be valid");
    let context = DeployContext {
        content_root: &harness.content_root,
        credential_root: &harness.credential_root,
        engine_state: &harness.engine_state,
    };

    let first_id = "123e4567-e89b-12d3-a456-426614174000";
    let first_request = DeployRequest::parse(SITE_ID, &remote.head, first_id, Some(key.as_str()))
        .expect("request should be valid");
    let first_result = execute(
        &context,
        &manifest,
        &first_request,
        &CancellationToken::default(),
    )
    .expect("first deploy should succeed");

    let retry_id = "9b2f1c34-5678-4abc-9def-0123456789ab";
    let retry_request = DeployRequest::parse(SITE_ID, &remote.head, retry_id, Some(key.as_str()))
        .expect("retry request should be valid");
    let retry_result = execute(
        &context,
        &manifest,
        &retry_request,
        &CancellationToken::default(),
    )
    .expect("replay should resolve to the original outcome");

    assert_eq!(retry_result.release_id, first_result.release_id);
    assert_eq!(
        retry_result.release_id.to_string(),
        first_id,
        "the retry must not create its own release"
    );
    let retried_release = harness
        ._content_dir
        .path()
        .join(format!("sites/{SITE_ID}/releases/{retry_id}"));
    assert!(
        !retried_release.exists(),
        "a replayed retry must not stage a second release"
    );
}

#[test]
fn a_revision_not_on_an_allowed_branch_fails_without_activating_anything_and_frees_the_lock() {
    let remote = local_remote();
    let harness = harness();
    let manifest = SiteManifest::from_json_for_site(&manifest_json(&remote), site_id())
        .expect("manifest should be valid");
    let unrelated = "a".repeat(40);
    let request_id = "123e4567-e89b-12d3-a456-426614174000";
    let request = DeployRequest::parse(SITE_ID, &unrelated, request_id, None)
        .expect("request should be valid");
    let context = DeployContext {
        content_root: &harness.content_root,
        credential_root: &harness.credential_root,
        engine_state: &harness.engine_state,
    };

    let outcome = execute(&context, &manifest, &request, &CancellationToken::default());
    assert!(matches!(outcome, Err(DeployError::Resolve(_))));
    assert!(
        !harness
            ._content_dir
            .path()
            .join(format!("sites/{SITE_ID}/current"))
            .exists(),
        "a rejected revision must never activate a release"
    );

    // The lock must be free again: a follow-up attempt for the real HEAD
    // should proceed normally rather than reporting a conflict.
    let retry_id = "9b2f1c34-5678-4abc-9def-0123456789ab";
    let retry = DeployRequest::parse(SITE_ID, &remote.head, retry_id, None)
        .expect("retry request should be valid");
    execute(&context, &manifest, &retry, &CancellationToken::default())
        .expect("a fresh attempt after a rejected one should succeed");
}
