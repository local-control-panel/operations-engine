use super::*;
use std::{cell::RefCell, collections::HashMap};

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const ORIGIN: &str = "https://updates.example.test";
/// 2026-11-09T12:00:00Z
const NOW: i64 = 1_794_225_600;

fn managed(dir: &Path) -> ManagedRoot {
    ManagedRoot::open(&crate::site::TrustedRoot::parse(dir).unwrap()).unwrap()
}

fn rid() -> RequestId {
    RequestId::parse(ID).unwrap()
}

type Answer = Result<Option<(Vec<u8>, Option<String>)>, FetchError>;

/// Serves canned answers once and records every URL asked for.
#[derive(Default)]
struct Fake {
    answers: RefCell<HashMap<String, Answer>>,
    asked: RefCell<Vec<(String, Option<String>)>>,
}

impl Fake {
    fn serve(&self, path: &str, body: &[u8], etag: Option<&str>) {
        self.answers.borrow_mut().insert(
            format!("{ORIGIN}{path}"),
            Ok(Some((body.to_vec(), etag.map(str::to_owned)))),
        );
    }
    fn not_modified(&self, path: &str) {
        self.answers
            .borrow_mut()
            .insert(format!("{ORIGIN}{path}"), Ok(None));
    }
    fn fail(&self, path: &str, error: FetchError) {
        self.answers
            .borrow_mut()
            .insert(format!("{ORIGIN}{path}"), Err(error));
    }
    fn requests(&self) -> usize {
        self.asked.borrow().len()
    }
}

impl Fetch for Fake {
    fn get(&self, url: &str, max_bytes: u64, etag: Option<&str>) -> Result<Fetched, FetchError> {
        self.asked
            .borrow_mut()
            .push((url.to_owned(), etag.map(str::to_owned)));
        match self.answers.borrow_mut().remove(url) {
            Some(Ok(Some((bytes, etag)))) => {
                if bytes.len() as u64 > max_bytes {
                    Err(FetchError::TooLarge)
                } else {
                    Ok(Fetched::Body { bytes, etag })
                }
            }
            Some(Ok(None)) => Ok(Fetched::NotModified),
            Some(Err(error)) => Err(error),
            None => Err(FetchError::Unreachable),
        }
    }
}

fn manifest(sequence: u64, published: &str, expires: &str) -> Vec<u8> {
    format!(
        r#"{{"schemaVersion":1,"sequence":{sequence},"publishedAt":"{published}","expiresAt":"{expires}","advisories":[{{"id":"php-rce","title":"PHP","severity":"critical","status":"action-required"}}],"fixes":[],"revoked":[]}}"#
    )
    .into_bytes()
}

fn index(sequence: u64, published: &str, expires: &str, manifest: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"schemaVersion":1,"sequence":{sequence},"publishedAt":"{published}","expiresAt":"{expires}","manifest":{{"path":"/releases/{sequence:06}/manifest.json","bytes":{},"sha256":"{}"}}}}"#,
        manifest.len(),
        hex(&Sha256::digest(manifest)),
    )
    .into_bytes()
}

/// Publishes snapshot `sequence`, valid 30 days from `2026-11-08T12:00:00Z`.
fn publish(fake: &Fake, sequence: u64) {
    let m = manifest(sequence, "2026-11-08T12:00:00Z", "2026-12-08T12:00:00Z");
    fake.serve(
        "/feed/v1/index.json",
        &index(sequence, "2026-11-08T12:00:00Z", "2026-12-08T12:00:00Z", &m),
        Some("\"etag-1\""),
    );
    fake.serve(&format!("/releases/{sequence:06}/manifest.json"), &m, None);
}

fn enabled() -> (tempfile::TempDir, ManagedRoot) {
    let dir = tempfile::tempdir().unwrap();
    let state = managed(dir.path());
    set_policy(&state, Mode::CheckOnly, rid()).unwrap();
    (dir, state)
}

#[test]
fn utc_times_parse_exactly() {
    assert_eq!(parse_utc("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(parse_utc("2026-11-09T12:00:00Z"), Some(NOW));
    for bad in [
        "2026-11-09T12:00:00",
        "2026-11-09 12:00:00Z",
        "2026-11-09T12:00:00.5Z",
        "2026-11-09T12:00:00+02:00",
        "2026-13-09T12:00:00Z",
        "2026-11-09T24:00:00Z",
        "2026-11-0aT12:00:00Z",
        "",
    ] {
        assert_eq!(parse_utc(bad), None, "{bad}");
    }
}

#[test]
fn manifest_paths_are_strict() {
    assert!(manifest_path_ok("/releases/000002/manifest.json"));
    for bad in [
        "/feed/v1/index.json",
        "/releases/../etc/x.json",
        "/releases//x.json",
        "/releases/000002/manifest.json?x=1",
        "/releases/000002/manifest.json#a",
        "/releases/a b/manifest.json",
        "https://evil.test/releases/1/manifest.json",
        "/releases/000002/manifest.txt",
        "releases/000002/manifest.json",
    ] {
        assert!(!manifest_path_ok(bad), "{bad}");
    }
}

#[test]
fn nothing_is_fetched_unless_the_policy_is_check_only() {
    let dir = tempfile::tempdir().unwrap();
    let state = managed(dir.path());
    let fake = Fake::default();
    publish(&fake, 1);
    assert!(matches!(
        refresh(&state, &fake, ORIGIN, NOW, rid()),
        Err(Error::PolicyNotEnabled)
    ));
    set_policy(&state, Mode::Off, rid()).unwrap();
    assert!(matches!(
        refresh(&state, &fake, ORIGIN, NOW, rid()),
        Err(Error::PolicyNotEnabled)
    ));
    // An unknown mode is not read as permission.
    state
        .write_atomic(
            &rel(POLICY_FILE),
            br#"{"schemaVersion":1,"mode":"automatic"}"#,
        )
        .unwrap();
    assert_eq!(read_policy(&state), PolicyState::Invalid);
    assert!(matches!(
        refresh(&state, &fake, ORIGIN, NOW, rid()),
        Err(Error::PolicyNotEnabled)
    ));
    assert_eq!(fake.requests(), 0);
}

#[test]
fn a_valid_feed_is_accepted_and_reported_fresh() {
    let (_dir, state) = enabled();
    let fake = Fake::default();
    publish(&fake, 1);
    let done = refresh(&state, &fake, ORIGIN, NOW, rid()).unwrap();
    assert_eq!(done.result, "updated");
    assert_eq!(done.freshness, Freshness::Fresh);
    assert_eq!(done.sequence, Some(1));
    assert_eq!(fake.requests(), 2);
    let report = status(&state, NOW);
    assert_eq!(report.policy, PolicyState::CheckOnly);
    assert_eq!(report.freshness, Freshness::Fresh);
    let accepted = report.accepted.unwrap();
    assert_eq!(accepted.advisories[0].id, "php-rce");
    assert_eq!(accepted.revoked_count, 0);
    assert_eq!(report.last_check.unwrap().result, "updated");
}

#[test]
fn the_same_sequence_does_not_fetch_the_manifest_again_and_sends_the_etag() {
    let (_dir, state) = enabled();
    let fake = Fake::default();
    publish(&fake, 1);
    refresh(&state, &fake, ORIGIN, NOW, rid()).unwrap();
    let before = fake.requests();
    let m = manifest(1, "2026-11-08T12:00:00Z", "2026-12-08T12:00:00Z");
    fake.serve(
        "/feed/v1/index.json",
        &index(1, "2026-11-08T12:00:00Z", "2026-12-08T12:00:00Z", &m),
        Some("\"etag-2\""),
    );
    let again = refresh(&state, &fake, ORIGIN, NOW + 3600, rid()).unwrap();
    assert_eq!(again.result, "unchanged");
    assert_eq!(fake.requests(), before + 1, "only the index");
    assert_eq!(
        fake.asked.borrow().last().unwrap().1.as_deref(),
        Some("\"etag-1\"")
    );
    fake.not_modified("/feed/v1/index.json");
    assert_eq!(
        refresh(&state, &fake, ORIGIN, NOW + 7200, rid())
            .unwrap()
            .result,
        "unchanged"
    );
    assert_eq!(
        fake.asked.borrow().last().unwrap().1.as_deref(),
        Some("\"etag-2\"")
    );
}

#[test]
fn a_lower_sequence_or_another_hash_at_the_same_sequence_is_a_replay() {
    let (_dir, state) = enabled();
    let fake = Fake::default();
    publish(&fake, 2);
    refresh(&state, &fake, ORIGIN, NOW, rid()).unwrap();

    publish(&fake, 1);
    assert_eq!(
        refresh(&state, &fake, ORIGIN, NOW, rid()).unwrap().result,
        "replay"
    );
    assert_eq!(status(&state, NOW).accepted.unwrap().sequence, 2);

    // Same sequence, different manifest bytes.
    let other = manifest(2, "2026-11-08T12:00:00Z", "2026-12-08T12:00:01Z");
    fake.serve(
        "/feed/v1/index.json",
        &index(2, "2026-11-08T12:00:00Z", "2026-12-08T12:00:01Z", &other),
        None,
    );
    assert_eq!(
        refresh(&state, &fake, ORIGIN, NOW, rid()).unwrap().result,
        "replay"
    );
    assert_eq!(
        status(&state, NOW).accepted.unwrap().expires_at_unix,
        parse_utc("2026-12-08T12:00:00Z").unwrap()
    );
}

#[test]
fn a_manifest_that_does_not_match_its_hash_or_index_is_refused() {
    let (_dir, state) = enabled();
    let fake = Fake::default();
    let good = manifest(1, "2026-11-08T12:00:00Z", "2026-12-08T12:00:00Z");
    fake.serve(
        "/feed/v1/index.json",
        &index(1, "2026-11-08T12:00:00Z", "2026-12-08T12:00:00Z", &good),
        None,
    );
    let mut tampered = good.clone();
    tampered[20] ^= 1;
    fake.serve("/releases/000001/manifest.json", &tampered, None);
    assert_eq!(
        refresh(&state, &fake, ORIGIN, NOW, rid()).unwrap().result,
        "invalid"
    );
    assert!(status(&state, NOW).accepted.is_none());

    // The hash matches but the manifest says another sequence.
    let wrong = manifest(7, "2026-11-08T12:00:00Z", "2026-12-08T12:00:00Z");
    fake.serve(
        "/feed/v1/index.json",
        &index(1, "2026-11-08T12:00:00Z", "2026-12-08T12:00:00Z", &wrong),
        None,
    );
    fake.serve("/releases/000001/manifest.json", &wrong, None);
    assert_eq!(
        refresh(&state, &fake, ORIGIN, NOW, rid()).unwrap().result,
        "invalid"
    );
    // The hash matches but the times differ from the index.
    let skewed = manifest(1, "2026-11-08T12:00:00Z", "2026-12-07T12:00:00Z");
    fake.serve(
        "/feed/v1/index.json",
        &index(1, "2026-11-08T12:00:00Z", "2026-12-08T12:00:00Z", &skewed),
        None,
    );
    fake.serve("/releases/000001/manifest.json", &skewed, None);
    assert_eq!(
        refresh(&state, &fake, ORIGIN, NOW, rid()).unwrap().result,
        "invalid"
    );
    assert!(status(&state, NOW).accepted.is_none());
}

#[test]
fn an_expired_feed_is_not_accepted_and_an_accepted_one_turns_expired() {
    let (_dir, state) = enabled();
    let fake = Fake::default();
    publish(&fake, 1);
    let late = parse_utc("2026-12-09T00:00:00Z").unwrap();
    assert_eq!(
        refresh(&state, &fake, ORIGIN, late, rid()).unwrap().result,
        "expired"
    );
    assert!(status(&state, late).accepted.is_none());
    assert_eq!(status(&state, late).freshness, Freshness::Unknown);

    publish(&fake, 1);
    refresh(&state, &fake, ORIGIN, NOW, rid()).unwrap();
    // A 304 later does not extend it.
    fake.not_modified("/feed/v1/index.json");
    let done = refresh(&state, &fake, ORIGIN, late, rid()).unwrap();
    assert_eq!(done.result, "unchanged");
    assert_eq!(done.freshness, Freshness::Expired);
    assert_eq!(status(&state, late).freshness, Freshness::Expired);
}

#[test]
fn an_unreachable_origin_a_redirect_and_an_oversized_answer_change_nothing() {
    let (_dir, state) = enabled();
    let fake = Fake::default();
    for error in [
        FetchError::Unreachable,
        FetchError::Redirect,
        FetchError::TooLarge,
        FetchError::Status(503),
    ] {
        fake.fail("/feed/v1/index.json", error);
        let done = refresh(&state, &fake, ORIGIN, NOW, rid()).unwrap();
        assert_eq!(done.result, "unreachable");
        assert_eq!(done.freshness, Freshness::Unknown);
    }
    publish(&fake, 1);
    refresh(&state, &fake, ORIGIN, NOW, rid()).unwrap();
    fake.fail("/feed/v1/index.json", FetchError::Unreachable);
    let done = refresh(&state, &fake, ORIGIN, NOW + 60, rid()).unwrap();
    assert_eq!(done.result, "unreachable");
    assert_eq!(done.freshness, Freshness::Fresh, "the accepted feed stays");
    assert_eq!(status(&state, NOW).accepted.unwrap().sequence, 1);
}

#[test]
fn an_unreliable_clock_and_a_future_dated_feed_fail_closed() {
    let (_dir, state) = enabled();
    let fake = Fake::default();
    publish(&fake, 1);
    assert_eq!(
        refresh(&state, &fake, ORIGIN, 1_000, rid()).unwrap().result,
        "clockUnreliable"
    );
    assert_eq!(fake.requests(), 0, "no request on an unreliable clock");
    let before_publication = parse_utc("2026-11-01T00:00:00Z").unwrap();
    assert_eq!(
        refresh(&state, &fake, ORIGIN, before_publication, rid())
            .unwrap()
            .result,
        "clockUnreliable"
    );
    assert!(status(&state, NOW).accepted.is_none());
}

#[test]
fn only_the_https_origin_or_loopback_is_used() {
    for good in [
        "https://updates.orbden.com",
        "http://127.0.0.1:8080",
        "http://localhost:9",
    ] {
        assert!(origin_ok(good), "{good}");
    }
    for bad in [
        "http://updates.orbden.com",
        "https://updates.orbden.com/feed",
        "https://u@evil.test",
        "https://",
        "ftp://x",
        "https://a.test?x=1",
        "",
    ] {
        assert!(!origin_ok(bad), "{bad}");
    }
    let (_dir, state) = enabled();
    let fake = Fake::default();
    publish(&fake, 1);
    assert_eq!(
        refresh(&state, &fake, "http://updates.example.test", NOW, rid())
            .unwrap()
            .result,
        "invalid"
    );
    assert_eq!(fake.requests(), 0);
}
