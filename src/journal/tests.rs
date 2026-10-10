use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::{cli::Cli, error::ErrorCode, protocol::Response, site::TrustedRoot};
use clap::Parser;

const ID_1: &str = "123e4567-e89b-12d3-a456-426614174001";
const ID_2: &str = "123e4567-e89b-12d3-a456-426614174002";
const SITE: &str = "223e4567-e89b-12d3-a456-426614174000";

fn state() -> (tempfile::TempDir, ManagedRoot) {
    let directory = tempfile::tempdir().unwrap();
    let root = ManagedRoot::open(&TrustedRoot::parse(directory.path()).unwrap()).unwrap();
    (directory, root)
}

fn raw(action: &str) -> RawEntry<'_> {
    RawEntry {
        actor: "admin@example.com",
        action,
        result: "ok",
        ..RawEntry::default()
    }
}

fn entry(action: &str) -> NewEntry {
    NewEntry::parse(raw(action)).unwrap()
}

fn rid(n: u32) -> RequestId {
    RequestId::parse(&format!("123e4567-e89b-12d3-a456-4266141{n:05}")).unwrap()
}

fn add(root: &ManagedRoot, e: &NewEntry, n: u32, now: u64) -> AppendOutcome {
    append(root, e, rid(n), None, Source::Api, now).unwrap()
}

fn page(root: &ManagedRoot, query: &Query) -> ListOutcome {
    list(root, query).unwrap()
}

#[test]
fn valid_entries_parse_and_bad_fields_are_rejected() {
    assert!(NewEntry::parse(raw("cms.adminLogin")).is_ok());
    assert!(NewEntry::parse(raw("wordpress.updateCore")).is_ok());
    assert!(
        NewEntry::parse(RawEntry {
            site: Some(SITE),
            operation_id: Some(ID_1),
            target: Some("user:admin"),
            error_code: Some("SUBPROCESS_FAILED"),
            summary: Some("Updated core 6.5 -> 6.6"),
            ..raw("site.deploy")
        })
        .is_ok()
    );

    for action in [
        "deploy",
        "nope.deploy",
        "site.Deploy",
        "site.",
        "site.a.b.c.d",
        "site.deploy now",
        "site.dep-loy",
    ] {
        assert!(NewEntry::parse(raw(action)).is_err(), "{action}");
    }
    for actor in ["", "has space", "a/b", "x?y=1", &"a".repeat(65)] {
        assert!(
            NewEntry::parse(RawEntry {
                actor,
                ..raw("site.deploy")
            })
            .is_err(),
            "{actor}"
        );
    }
    assert!(
        NewEntry::parse(RawEntry {
            result: "maybe",
            ..raw("site.deploy")
        })
        .is_err()
    );
    assert!(
        NewEntry::parse(RawEntry {
            site: Some("a b"),
            ..raw("site.deploy")
        })
        .is_err()
    );
    assert!(
        NewEntry::parse(RawEntry {
            error_code: Some("lower"),
            ..raw("site.deploy")
        })
        .is_err()
    );
}

#[test]
fn urls_secrets_and_login_links_are_rejected_without_echo() {
    for text in [
        "login https://example.com/wp-login.php?key=abc",
        "see www.example.com",
        "open /wp-admin/?action=login&token=1",
        "password=hunter2",
        "Password: hunter2",
        "token = abcdef",
        "Authorization: x",
        "Bearer abc",
        "api_key:abc",
        "eyJhbGciOiJIUzI1NiJ9",
        "AKIAABCDEFGHIJKLMNOP",
        "ghp_abc123",
        "-----BEGIN PRIVATE KEY-----",
        &"a1B2".repeat(10),
        "line\nbreak",
        "",
        &"x ".repeat(101),
    ] {
        let err = NewEntry::parse(RawEntry {
            summary: Some(text),
            ..raw("site.deploy")
        })
        .expect_err(text);
        assert_eq!(err.message(), "summary is not allowed");
    }
    // Harmless prose with a UUID, a version and a hyphenated word passes.
    assert!(
        NewEntry::parse(RawEntry {
            summary: Some(
                "Rolled back to release 20260101T000000Z (op 123e4567-e89b-12d3-a456-426614174001)"
            ),
            ..raw("site.rollback")
        })
        .is_ok()
    );
    // Identifier fields cannot carry a link or a long token either.
    for target in ["https://x/y", "user?token=1", &"a".repeat(50), "a b"] {
        assert!(
            NewEntry::parse(RawEntry {
                target: Some(target),
                ..raw("cms.adminLogin")
            })
            .is_err(),
            "{target}"
        );
    }
}

#[test]
fn append_assigns_increasing_seq_and_private_modes() {
    let (dir, root) = state();
    let first = add(&root, &entry("site.deploy"), 1, 100);
    let second = add(&root, &entry("site.rollback"), 2, 101);
    assert_eq!((first.entry.seq, second.entry.seq), (1, 2));
    assert!(!first.replayed);
    assert_eq!(first.entry.at_unix_secs, 100);
    assert_eq!(first.entry.source, Source::Api);

    let mode = |p: &str| {
        std::fs::metadata(dir.path().join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode("journal"), 0o700);
    assert_eq!(mode("journal/events.jsonl"), 0o600);
    assert_eq!(mode("journal/journal.lock"), 0o600);
}

#[test]
fn a_loose_existing_file_is_tightened() {
    let (dir, root) = state();
    add(&root, &entry("site.deploy"), 1, 1);
    let path = dir.path().join("journal/events.jsonl");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    add(&root, &entry("site.deploy"), 2, 2);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn a_retry_returns_the_original_entry_by_request_id_or_key() {
    let (_dir, root) = state();
    let first = add(&root, &entry("site.deploy"), 1, 100);
    let again = append(&root, &entry("site.deploy"), rid(1), None, Source::Api, 999).unwrap();
    assert!(again.replayed);
    assert_eq!(again.entry, first.entry);

    let key = IdempotencyKey::parse("k-1").unwrap();
    let keyed = append(
        &root,
        &entry("site.rollback"),
        rid(2),
        Some(&key),
        Source::Api,
        5,
    )
    .unwrap();
    let retried = append(
        &root,
        &entry("site.rollback"),
        rid(3),
        Some(&key),
        Source::Api,
        6,
    )
    .unwrap();
    assert!(retried.replayed);
    assert_eq!(retried.entry.id, keyed.entry.id);
    assert_eq!(page(&root, &Query::default()).entries.len(), 2);
}

#[test]
fn list_is_newest_first_and_filters_combine() {
    let (_dir, root) = state();
    let site_a = NewEntry::parse(RawEntry {
        site: Some("a"),
        ..raw("cms.adminLogin")
    })
    .unwrap();
    let site_b = NewEntry::parse(RawEntry {
        site: Some("b"),
        ..raw("wordpress.updateCore")
    })
    .unwrap();
    let denied = NewEntry::parse(RawEntry {
        site: Some("a"),
        result: "denied",
        ..raw("cms.cacheClear")
    })
    .unwrap();
    add(&root, &site_a, 1, 10);
    add(&root, &site_b, 2, 20);
    add(&root, &denied, 3, 30);
    append(
        &root,
        &entry("engine.install"),
        rid(4),
        None,
        Source::Engine,
        40,
    )
    .unwrap();

    let all = page(&root, &Query::default());
    assert_eq!(
        all.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
        [4, 3, 2, 1]
    );
    assert_eq!(all.next_cursor, None);

    let by_site = page(
        &root,
        &Query {
            site: Some("a".into()),
            ..Query::default()
        },
    );
    assert_eq!(by_site.entries.len(), 2);
    let by_prefix = page(
        &root,
        &Query {
            action_prefix: Some("cms.".into()),
            ..Query::default()
        },
    );
    assert_eq!(by_prefix.entries.len(), 2);
    let since = page(
        &root,
        &Query {
            since_unix_secs: Some(30),
            ..Query::default()
        },
    );
    assert_eq!(since.entries.len(), 2);
    let result = page(
        &root,
        &Query {
            result: Some(JournalResult::Denied),
            ..Query::default()
        },
    );
    assert_eq!(result.entries.len(), 1);
    let source = page(
        &root,
        &Query {
            source: Some(Source::Engine),
            ..Query::default()
        },
    );
    assert_eq!(source.entries[0].action, "engine.install");
    let combined = page(
        &root,
        &Query {
            site: Some("a".into()),
            action_prefix: Some("cms.admin".into()),
            since_unix_secs: Some(5),
            ..Query::default()
        },
    );
    assert_eq!(combined.entries.len(), 1);
}

#[test]
fn pagination_walks_every_entry_once() {
    let (_dir, root) = state();
    for n in 1..=7 {
        add(&root, &entry("site.deploy"), n, u64::from(n));
    }
    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let result = page(
            &root,
            &Query {
                limit: Some(3),
                before_seq: cursor,
                ..Query::default()
            },
        );
        seen.extend(result.entries.iter().map(|e| e.seq));
        match result.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(seen, [7, 6, 5, 4, 3, 2, 1]);
    // limit 0 clamps to 1, huge clamps to the maximum.
    assert_eq!(
        page(
            &root,
            &Query {
                limit: Some(0),
                ..Query::default()
            }
        )
        .entries
        .len(),
        1
    );
    assert_eq!(
        page(
            &root,
            &Query {
                limit: Some(10_000),
                ..Query::default()
            }
        )
        .entries
        .len(),
        7
    );
}

#[test]
fn listing_a_missing_journal_is_empty_and_creates_nothing() {
    let (dir, root) = state();
    let result = page(&root, &Query::default());
    assert!(result.entries.is_empty());
    assert!(!dir.path().join("journal").exists());
}

#[test]
fn corrupt_and_torn_lines_are_skipped_counted_and_healed() {
    let (dir, root) = state();
    add(&root, &entry("site.deploy"), 1, 1);
    let path = dir.path().join("journal/events.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    use std::io::Write as _;
    file.write_all(b"not json\n\xff\xfe\n{\"seq\":1}\n{\"schemaVersion\":1,\"seq\":9,\"id\"")
        .unwrap();
    drop(file);

    let before = page(&root, &Query::default());
    assert_eq!(before.entries.len(), 1);
    assert_eq!(before.skipped, 4);

    // The torn last line does not swallow the next entry.
    let next = add(&root, &entry("site.rollback"), 2, 2);
    assert_eq!(next.entry.seq, 2);
    let after = page(&root, &Query::default());
    assert_eq!(
        after.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
        [2, 1]
    );
}

#[test]
fn rotation_keeps_seq_order_and_prunes_old_segments() {
    let (dir, root) = state();
    let limits = Limits {
        segment_bytes: 700,
        segments: 2,
    };
    for n in 1..=40 {
        append_with(
            &root,
            &entry("site.deploy"),
            rid(n),
            None,
            Source::Api,
            u64::from(n),
            &limits,
        )
        .unwrap();
    }
    let names: Vec<String> = std::fs::read_dir(dir.path().join("journal"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("events."))
        .collect();
    assert!(names.contains(&"events.jsonl".to_owned()));
    assert_eq!(names.len(), 3, "active + 2 rotated: {names:?}");
    for name in &names {
        let mode = std::fs::metadata(dir.path().join("journal").join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{name}");
    }

    let all = page(
        &root,
        &Query {
            limit: Some(200),
            ..Query::default()
        },
    );
    let seqs: Vec<u64> = all.entries.iter().map(|e| e.seq).collect();
    assert_eq!(seqs[0], 40, "newest first across segments");
    assert!(
        seqs.windows(2).all(|w| w[0] == w[1] + 1),
        "contiguous: {seqs:?}"
    );
    assert!(seqs.len() < 40, "old segments were dropped");

    // The counter survives rotation and pruning.
    let next = append_with(
        &root,
        &entry("site.deploy"),
        rid(41),
        None,
        Source::Api,
        41,
        &limits,
    )
    .unwrap();
    assert_eq!(next.entry.seq, 41);

    // Cursor pagination crosses segment boundaries.
    let mut walked = Vec::new();
    let mut cursor = None;
    loop {
        let result = page(
            &root,
            &Query {
                limit: Some(4),
                before_seq: cursor,
                ..Query::default()
            },
        );
        walked.extend(result.entries.iter().map(|e| e.seq));
        match result.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert!(walked.windows(2).all(|w| w[0] == w[1] + 1));
    assert_eq!(walked[0], 41);
}

#[test]
fn seq_is_recovered_when_the_active_segment_is_empty_after_rotation() {
    let (dir, root) = state();
    let limits = Limits {
        segment_bytes: 300,
        segments: 5,
    };
    for n in 1..=6 {
        append_with(
            &root,
            &entry("site.deploy"),
            rid(n),
            None,
            Source::Api,
            1,
            &limits,
        )
        .unwrap();
    }
    std::fs::write(dir.path().join("journal/events.jsonl"), b"").unwrap();
    let next = append_with(
        &root,
        &entry("site.deploy"),
        rid(7),
        None,
        Source::Api,
        1,
        &limits,
    )
    .unwrap();
    // Entry 6 was lost with the emptied file; the counter continues after
    // the newest rotated segment instead of restarting.
    assert_eq!(next.entry.seq, 6);
}

#[test]
fn concurrent_appends_never_duplicate_or_lose_a_seq() {
    let (dir, _root) = state();
    let path = dir.path().to_owned();
    let threads: Vec<_> = (0..8u32)
        .map(|t| {
            let path = path.clone();
            std::thread::spawn(move || {
                let root = ManagedRoot::open(&TrustedRoot::parse(&path).unwrap()).unwrap();
                for i in 0..15u32 {
                    let n = t * 100 + i + 1;
                    append(&root, &entry("site.deploy"), rid(n), None, Source::Api, 1).unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let root = ManagedRoot::open(&TrustedRoot::parse(&path).unwrap()).unwrap();
    let all = page(
        &root,
        &Query {
            limit: Some(200),
            ..Query::default()
        },
    );
    assert_eq!(all.skipped, 0);
    let mut seqs: Vec<u64> = all.entries.iter().map(|e| e.seq).collect();
    seqs.sort_unstable();
    assert_eq!(seqs, (1..=120).collect::<Vec<u64>>());
}

#[test]
fn query_validation_rejects_bad_site_and_prefix() {
    assert!(
        Query {
            site: Some("a b".into()),
            ..Query::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Query {
            action_prefix: Some("cms?".into()),
            ..Query::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Query {
            action_prefix: Some(String::new()),
            ..Query::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Query {
            action_prefix: Some("cms.".into()),
            ..Query::default()
        }
        .validate()
        .is_ok()
    );
}

fn cli(args: &[&str]) -> Cli {
    Cli::try_parse_from(std::iter::once("ops-engine").chain(args.iter().copied())).unwrap()
}

fn failure() -> Response {
    Response::failure("site.deploy", ErrorCode::SubprocessFailed, "boom")
}

#[test]
fn auto_plan_covers_the_wired_operations_only() {
    let deploy = cli(&[
        "site",
        "deploy",
        "--site-id",
        SITE,
        "--revision",
        "abc",
        "--request-id",
        ID_1,
    ]);
    let plan = auto::plan(&deploy.command).unwrap();
    assert_eq!(plan.action, "site.deploy");
    assert_eq!(plan.site.as_deref(), Some(SITE));

    let engine = cli(&[
        "engine",
        "rollback",
        "--request-id",
        ID_2,
        "--idempotency-key",
        "k",
    ]);
    let plan = auto::plan(&engine.command).unwrap();
    assert_eq!((plan.action, plan.site), ("engine.rollback", None));
    assert!(plan.idempotency_key.is_some());

    let bad = cli(&[
        "site",
        "deploy",
        "--site-id",
        "not-a-uuid",
        "--revision",
        "a",
        "--request-id",
        ID_1,
    ]);
    assert!(auto::plan(&bad.command).is_none());
    assert!(auto::plan(&cli(&["site", "list"]).command).is_none());
    assert!(auto::plan(&cli(&["capabilities"]).command).is_none());
    // The journal does not journal itself.
    let append = cli(&["journal", "list"]);
    assert!(auto::plan(&append.command).is_none());
}

#[test]
fn auto_journal_records_outcomes_but_not_invalid_input() {
    let (_dir, root) = state();
    let deploy = cli(&[
        "site",
        "deploy",
        "--site-id",
        SITE,
        "--revision",
        "abc",
        "--request-id",
        ID_1,
    ]);
    let plan = auto::plan(&deploy.command).unwrap();

    auto::write(&root, &plan, &failure(), 50).unwrap();
    let invalid = Response::failure("site.deploy", ErrorCode::InvalidInput, "bad");
    let other = auto::plan(&cli(&["engine", "rollback", "--request-id", ID_2]).command).unwrap();
    auto::write(&root, &other, &invalid, 51).unwrap();

    let ok = Response::success("site.rollback", serde_json::json!({})).unwrap();
    let third = auto::plan(
        &cli(&[
            "site",
            "unenroll",
            "--site-id",
            SITE,
            "--request-id",
            "123e4567-e89b-12d3-a456-426614174003",
        ])
        .command,
    )
    .unwrap();
    auto::write(&root, &third, &ok, 52).unwrap();

    let all = page(&root, &Query::default());
    assert_eq!(all.entries.len(), 2);
    let newest = &all.entries[0];
    assert_eq!(newest.action, "site.unenroll");
    assert_eq!(newest.result, JournalResult::Ok);
    assert_eq!(newest.source, Source::Engine);
    assert_eq!(newest.actor, "engine");
    assert_eq!(
        newest.operation_id.as_deref(),
        Some("123e4567-e89b-12d3-a456-426614174003")
    );
    let oldest = &all.entries[1];
    assert_eq!(oldest.result, JournalResult::Failed);
    assert_eq!(oldest.error_code.as_deref(), Some("SUBPROCESS_FAILED"));
    assert_eq!(oldest.site.as_deref(), Some(SITE));

    // A replayed operation does not journal twice.
    auto::write(&root, &plan, &failure(), 60).unwrap();
    assert_eq!(page(&root, &Query::default()).entries.len(), 2);
}

#[test]
fn stored_lines_contain_no_unexpected_fields() {
    let (dir, root) = state();
    add(
        &root,
        &NewEntry::parse(RawEntry {
            site: Some("s"),
            summary: Some("ok"),
            ..raw("cms.adminLogin")
        })
        .unwrap(),
        1,
        1,
    );
    let text = std::fs::read_to_string(dir.path().join("journal/events.jsonl")).unwrap();
    let value: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    let mut keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "action",
            "actor",
            "atUnixSecs",
            "id",
            "result",
            "schemaVersion",
            "seq",
            "site",
            "source",
            "summary"
        ]
    );
}
