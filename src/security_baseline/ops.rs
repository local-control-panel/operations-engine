//! The four operations. See the module docs in `mod.rs` for the contract.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    ACCEPT, ALGORITHM, CAPTURE, COMPARE, Kind, MAX_LISTED_PATHS, PRUNE, RETAINED_GENERATIONS,
    SCHEMA_VERSION, Scope,
    scan::{self, Limits},
    store::{self, Generation, Index, LimitsRecord, Store},
};
use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    journal::{self, NewEntry, RawEntry, Source},
    mutation::preflight,
    site::{SiteId, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Op {
    Capture,
    Compare,
    Accept,
    Prune,
}

impl Op {
    const fn name(self) -> &'static str {
        match self {
            Self::Capture => CAPTURE,
            Self::Compare => COMPARE,
            Self::Accept => ACCEPT,
            Self::Prune => PRUNE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PruneMode {
    /// Drop the candidate; the accepted generation and its history stay.
    Candidate,
    /// Drop everything except the accepted generation and the candidate.
    Superseded,
    /// Remove the whole baseline of the site.
    All,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    site_id: String,
    project_root: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    subsite: Option<String>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    generation: Option<u32>,
    #[serde(default)]
    digest: Option<String>,
    #[serde(default)]
    mode: Option<String>,
}

#[derive(Debug)]
pub struct Request {
    pub op: Op,
    site_id: SiteId,
    kind: Option<Kind>,
    project_root: PathBuf,
    subsite: Option<String>,
    actor: Option<String>,
    generation: Option<u32>,
    digest: Option<String>,
    mode: Option<PruneMode>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidSite,
    InvalidKind,
    InvalidRoot,
    InvalidSubsite,
    InvalidActor,
    InvalidGeneration,
    InvalidDigest,
    InvalidMode,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

fn token_ok(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

impl Request {
    pub fn parse(
        op: Op,
        json: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let site_id = SiteId::parse(&plan.site_id).map_err(|_| RequestError::InvalidSite)?;
        let project_root =
            super::project_root_ok(&plan.project_root).ok_or(RequestError::InvalidRoot)?;
        let needs_kind = op != Op::Prune;
        let kind = match (&plan.kind, needs_kind) {
            (Some(kind), true) => Some(Kind::parse(kind).ok_or(RequestError::InvalidKind)?),
            (None, false) => None,
            _ => return Err(RequestError::InvalidKind),
        };
        if let Some(subsite) = &plan.subsite {
            if op == Op::Prune || !token_ok(subsite, 64) {
                return Err(RequestError::InvalidSubsite);
            }
        }
        let mutating = op != Op::Compare;
        match (&plan.actor, mutating) {
            (Some(actor), true) if token_ok(&actor.replace([':', '@', '+'], "-"), 64) => {}
            (None, false) => {}
            _ => return Err(RequestError::InvalidActor),
        }
        let generation_allowed = matches!(op, Op::Compare | Op::Accept);
        match (plan.generation, op) {
            (Some(0), _) => return Err(RequestError::InvalidGeneration),
            (Some(_), _) if generation_allowed => {}
            (None, Op::Capture | Op::Compare | Op::Prune) => {}
            _ => return Err(RequestError::InvalidGeneration),
        }
        match (&plan.digest, op) {
            (Some(digest), Op::Accept)
                if digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) => {}
            (None, Op::Capture | Op::Compare | Op::Prune) => {}
            _ => return Err(RequestError::InvalidDigest),
        }
        let mode = match (plan.mode.as_deref(), op) {
            (Some("candidate"), Op::Prune) => Some(PruneMode::Candidate),
            (Some("superseded"), Op::Prune) => Some(PruneMode::Superseded),
            (Some("all"), Op::Prune) => Some(PruneMode::All),
            (None, Op::Capture | Op::Compare | Op::Accept) => None,
            _ => return Err(RequestError::InvalidMode),
        };
        Ok(Self {
            op,
            site_id,
            kind,
            project_root,
            subsite: plan.subsite,
            actor: plan.actor,
            generation: plan.generation,
            digest: plan.digest,
            mode,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }

    pub fn root(&self) -> &Path {
        &self.project_root
    }
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// Content roots the canonical project root has to be inside of.
    pub content_roots: Vec<PathBuf>,
    pub limits: Limits,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    ResourceBusy,
    /// The project root is missing, not a directory or outside the content roots.
    Root(&'static str),
    Invalid(&'static str),
    Conflict(&'static str),
    /// The stored baseline cannot be read.
    Store(&'static str),
    PostCommit {
        result: Value,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) | Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another operation is already in progress for this site".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Root(message) | Self::Invalid(message) => {
                (ErrorCode::InvalidInput, (*message).into())
            }
            Self::Conflict(message) => (ErrorCode::Conflict, (*message).into()),
            Self::Store(message) => (ErrorCode::Internal, (*message).into()),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal security baseline error".into(),
            ),
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct Target {
    root: ManagedRoot,
    canonical: String,
}

fn open_target(ctx: &Context<'_>, req: &Request) -> Result<Target, Error> {
    let canonical = std::fs::canonicalize(&req.project_root)
        .map_err(|_| Error::Root("the project root does not exist"))?;
    if !ctx
        .content_roots
        .iter()
        .any(|root| canonical.starts_with(root))
    {
        return Err(Error::Root(
            "project root is outside configured content roots",
        ));
    }
    let text = canonical
        .to_str()
        .ok_or(Error::Root("the project root is not valid UTF-8"))?
        .to_owned();
    let trusted =
        TrustedRoot::parse(&canonical).map_err(|_| Error::Root("the project root is invalid"))?;
    let root =
        ManagedRoot::open(&trusted).map_err(|_| Error::Root("the project root is unreadable"))?;
    Ok(Target {
        root,
        canonical: text,
    })
}

struct Diff {
    added: Vec<String>,
    changed: Vec<String>,
    deleted: Vec<String>,
}

fn diff(old: &[(String, String)], new: &BTreeMap<String, String>) -> Diff {
    let old: BTreeMap<&str, &str> = old.iter().map(|(p, h)| (p.as_str(), h.as_str())).collect();
    let mut out = Diff {
        added: vec![],
        changed: vec![],
        deleted: vec![],
    };
    for (path, hash) in new {
        match old.get(path.as_str()) {
            None => out.added.push(path.clone()),
            Some(previous) if previous != hash => out.changed.push(path.clone()),
            Some(_) => {}
        }
    }
    for path in old.keys() {
        if !new.contains_key(*path) {
            out.deleted.push((*path).to_owned());
        }
    }
    out
}

impl Diff {
    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.changed.is_empty() && self.deleted.is_empty()
    }

    fn json(&self) -> Value {
        let listed = |paths: &[String]| {
            paths
                .iter()
                .take(MAX_LISTED_PATHS)
                .cloned()
                .collect::<Vec<_>>()
        };
        json!({
            "added": self.added.len(),
            "changed": self.changed.len(),
            "deleted": self.deleted.len(),
            "addedPaths": listed(&self.added),
            "changedPaths": listed(&self.changed),
            "deletedPaths": listed(&self.deleted),
            "truncated": self.added.len() > MAX_LISTED_PATHS
                || self.changed.len() > MAX_LISTED_PATHS
                || self.deleted.len() > MAX_LISTED_PATHS,
        })
    }
}

fn limits_record(limits: &Limits) -> LimitsRecord {
    LimitsRecord {
        max_files: limits.max_files,
        max_bytes: limits.max_bytes,
        timeout_secs: limits.timeout.as_secs(),
    }
}

fn new_generation(
    req: &Request,
    target: &Target,
    limits: &Limits,
    number: u32,
    scan: scan::Scan,
) -> Generation {
    let kind = req.kind.expect("validated by the request");
    let digest = store::digest(&scan.files);
    let complete = scan.incomplete.is_none();
    Generation {
        schema_version: SCHEMA_VERSION,
        site_id: req.site_id.to_string(),
        subsite: req.subsite.clone(),
        kind: kind.name().into(),
        root: target.canonical.clone(),
        generation: number,
        created_at_unix_secs: now(),
        algorithm: ALGORITHM.into(),
        scope: Scope::for_kind(kind).id(),
        limits: limits_record(limits),
        file_count: scan.files.len(),
        bytes_read: scan.bytes_read,
        complete,
        incomplete_reason: scan.incomplete.map(|r| r.as_str().to_owned()),
        incomplete_path: scan.stopped_at,
        digest,
        files: scan.files.into_iter().collect(),
    }
}

/// Why a stored generation cannot be compared with the code now, if it cannot.
fn incomparable(stored: &Generation, req: &Request, target: &Target) -> Option<&'static str> {
    let kind = req.kind?;
    if stored.scope != Scope::for_kind(kind).id() || stored.kind != kind.name() {
        Some("scopeChanged")
    } else if stored.root != target.canonical {
        Some("rootChanged")
    } else if stored.subsite != req.subsite {
        Some("subsiteChanged")
    } else {
        None
    }
}

fn lock<'a>(
    ctx: &'a Context<'_>,
    req: &Request,
) -> Result<crate::transaction::lock::SiteLockGuard<'a>, Error> {
    resource_lock::acquire(ctx.engine_state, &req.project_root, req.request_id)
        .map_err(|_| Error::ResourceBusy)
}

/// Read-only comparison of the code on disk with a stored generation.
pub fn compare(ctx: &Context<'_>, req: &Request) -> Result<Value, Error> {
    let target = open_target(ctx, req)?;
    let _lock = lock(ctx, req)?;
    let site = req.site_id.to_string();
    let Some(store) = Store::open(ctx.engine_state, &site, false).map_err(Error::Io)? else {
        return Ok(json!({ "status": "noBaseline" }));
    };
    let Ok(index) = store.load_index() else {
        return Ok(json!({ "status": "unavailable", "reason": "baselineUnreadable" }));
    };
    let Some(number) = req.generation.or(index.accepted) else {
        return Ok(json!({ "status": "noBaseline", "candidateGeneration": index.candidate }));
    };
    if !index.generations.contains(&number) {
        return Err(Error::Invalid("that generation is not stored"));
    }
    let Ok(stored) = store.load_generation(number) else {
        return Ok(
            json!({ "status": "unavailable", "reason": "baselineUnreadable", "generation": number }),
        );
    };
    if !stored.complete {
        return Ok(
            json!({ "status": "unavailable", "reason": "baselineIncomplete", "generation": number }),
        );
    }
    if let Some(reason) = incomparable(&stored, req, &target) {
        return Ok(json!({ "status": "unavailable", "reason": reason, "generation": number }));
    }
    let scanned = scan::scan(
        &target.root,
        &Scope::for_kind(req.kind.unwrap()),
        &ctx.limits,
    );
    if let Some(reason) = scanned.incomplete {
        return Ok(json!({
            "status": "incomplete",
            "reason": reason.as_str(),
            "stoppedAt": scanned.stopped_at,
            "generation": number,
            "filesScanned": scanned.files.len(),
            "bytesRead": scanned.bytes_read,
        }));
    }
    let delta = diff(&stored.files, &scanned.files);
    let mut out = delta.json();
    let object = out.as_object_mut().unwrap();
    object.insert(
        "status".into(),
        json!(if delta.is_empty() { "match" } else { "differs" }),
    );
    object.insert("generation".into(), json!(number));
    object.insert("isAccepted".into(), json!(index.accepted == Some(number)));
    object.insert(
        "createdAtUnixSecs".into(),
        json!(stored.created_at_unix_secs),
    );
    object.insert(
        "acceptedAtUnixSecs".into(),
        json!(index.accepted_at_unix_secs),
    );
    object.insert("candidateGeneration".into(), json!(index.candidate));
    object.insert("filesScanned".into(), json!(scanned.files.len()));
    object.insert("bytesRead".into(), json!(scanned.bytes_read));
    Ok(out)
}

fn journal_record(
    ctx: &Context<'_>,
    req: &Request,
    action: &str,
    summary: &str,
    target: Option<&str>,
) -> bool {
    let site = req.site_id.to_string();
    let Ok(entry) = NewEntry::parse(RawEntry {
        actor: req.actor.as_deref().unwrap_or("engine"),
        action,
        result: "ok",
        site: Some(&site),
        subsite: req.subsite.as_deref(),
        target,
        summary: Some(summary),
        ..RawEntry::default()
    }) else {
        return false;
    };
    journal::append(
        ctx.engine_state,
        &entry,
        req.request_id,
        req.idempotency_key.as_ref(),
        Source::Engine,
        journal::unix_now_secs(),
    )
    .is_ok()
}

/// Keeps the accepted and candidate generations plus the newest others, at
/// most [`RETAINED_GENERATIONS`] in all.
fn apply_retention(store: &Store, index: &mut Index) {
    let mut keep: Vec<u32> = index.accepted.into_iter().chain(index.candidate).collect();
    let mut others: Vec<u32> = index
        .generations
        .iter()
        .copied()
        .filter(|g| !keep.contains(g))
        .collect();
    others.sort_unstable_by(|a, b| b.cmp(a));
    for generation in others {
        if keep.len() < RETAINED_GENERATIONS {
            keep.push(generation);
        } else {
            store.remove_generation(generation);
        }
    }
    keep.sort_unstable();
    index.generations = keep;
}

/// Wraps a mutation in the engine's usual lock, idempotency, transaction and
/// audit record.
fn mutate(
    ctx: &Context<'_>,
    req: &Request,
    work: impl FnOnce(&Store, &Target) -> Result<Value, Error>,
) -> Result<Value, Error> {
    let operation = req.op.name();
    let target = open_target(ctx, req)?;
    let hash = resource_lock::canonical_hash(&req.project_root);
    let scope_path = SiteRelativePath::parse(format!("security-baseline/{hash}")).unwrap();
    ctx.engine_state
        .create_dir_all(&scope_path)
        .map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&scope_path)
        .map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope
            .create_dir_all(&SiteRelativePath::parse(child).unwrap())
            .map_err(Error::Io)?;
    }
    let _resource_lock = lock(ctx, req)?;
    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        operation,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id, operation),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted {
        lock: tx_lock,
        mut state,
    } = admitted;
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();

    let site = req.site_id.to_string();
    let outcome = Store::open(ctx.engine_state, &site, true)
        .map_err(Error::Io)
        .and_then(|store| store.ok_or(Error::Store("baseline store is unavailable")))
        .and_then(|store| work(&store, &target));
    let result = match outcome {
        Ok(value) => value,
        Err(error) => {
            let (code, message) = error.protocol();
            let _ = state.mark_failed(code, message);
            let _ = state::save(&scope, &state_path, &state);
            let _ = audit::append(
                &scope,
                &audit_path,
                &AuditRecord::result(state.request_id, false, Some(code)),
            );
            return Err(error);
        }
    };
    state.mark_committed(result.clone()).unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(tx_lock);
        return Err(Error::PostCommit { result });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(tx_lock);
    Ok(result)
}

fn replay(scope: &ManagedRoot, id: RequestId, operation: &str) -> Result<Value, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => Ok(loaded.outcome.unwrap().result.unwrap()),
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn load_index(store: &Store) -> Result<Index, Error> {
    store
        .load_index()
        .map_err(|_| Error::Store("the stored baseline index is unreadable"))
}

/// Writes a new *candidate*. The accepted generation is never touched.
pub fn capture(ctx: &Context<'_>, req: &Request) -> Result<Value, Error> {
    mutate(ctx, req, |store, target| {
        let mut index = load_index(store)?;
        let number = index.next_generation.max(1);
        let scanned = scan::scan(
            &target.root,
            &Scope::for_kind(req.kind.unwrap()),
            &ctx.limits,
        );
        let generation = new_generation(req, target, &ctx.limits, number, scanned);
        let against_accepted = index
            .accepted
            .and_then(|accepted| store.load_generation(accepted).ok())
            .filter(|stored| incomparable(stored, req, target).is_none())
            .map(|stored| {
                let new: BTreeMap<String, String> = generation.files.iter().cloned().collect();
                diff(&stored.files, &new).json()
            });
        store.save_generation(&generation).map_err(Error::Io)?;
        let replaced = index.candidate.replace(number);
        index.next_generation = number + 1;
        index.generations.push(number);
        if let Some(old) = replaced {
            index.generations.retain(|g| *g != old);
            store.remove_generation(old);
        }
        apply_retention(store, &mut index);
        store.save_index(&index).map_err(Error::Io)?;
        store.sweep(&index);
        let summary = format!(
            "candidate generation {number}, {} files{}",
            generation.file_count,
            if generation.complete {
                ""
            } else {
                ", incomplete"
            }
        );
        let journaled = journal_record(
            ctx,
            req,
            "security.baselineCapture",
            &summary,
            Some(&format!("gen{number}")),
        );
        Ok(json!({
            "generation": number,
            "digest": generation.digest,
            "complete": generation.complete,
            "incompleteReason": generation.incomplete_reason,
            "stoppedAt": generation.incomplete_path,
            "fileCount": generation.file_count,
            "bytesRead": generation.bytes_read,
            "createdAtUnixSecs": generation.created_at_unix_secs,
            "acceptedGeneration": index.accepted,
            "diffFromAccepted": against_accepted,
            "journalRecorded": journaled,
        }))
    })
}

/// Makes the candidate the accepted generation, but only if the code on disk
/// still matches it (checked under the project lock).
pub fn accept(ctx: &Context<'_>, req: &Request) -> Result<Value, Error> {
    mutate(ctx, req, |store, target| {
        let mut index = load_index(store)?;
        let number = req.generation.unwrap();
        if index.candidate != Some(number) {
            return Err(Error::Invalid(
                "that generation is not the current candidate",
            ));
        }
        let candidate = store
            .load_generation(number)
            .map_err(|_| Error::Store("the candidate generation is unreadable"))?;
        if !candidate.complete {
            return Err(Error::Invalid("an incomplete capture cannot be accepted"));
        }
        if Some(candidate.digest.as_str()) != req.digest.as_deref() {
            return Err(Error::Conflict(
                "the candidate digest does not match what was reviewed",
            ));
        }
        if let Some(reason) = incomparable(&candidate, req, target) {
            return Err(Error::Conflict(match reason {
                "rootChanged" => "the project root changed since the capture",
                _ => "the scan scope changed since the capture",
            }));
        }
        let scanned = scan::scan(
            &target.root,
            &Scope::for_kind(req.kind.unwrap()),
            &ctx.limits,
        );
        if scanned.incomplete.is_some() {
            return Err(Error::Conflict(
                "the code could not be fully read to verify the candidate",
            ));
        }
        if store::digest(&scanned.files) != candidate.digest {
            return Err(Error::Conflict(
                "the code changed since the candidate was captured; capture again",
            ));
        }
        index.accepted = Some(number);
        index.candidate = None;
        index.accepted_at_unix_secs = Some(now());
        apply_retention(store, &mut index);
        store.save_index(&index).map_err(Error::Io)?;
        store.sweep(&index);
        let summary = format!(
            "accepted generation {number}, {} files",
            candidate.file_count
        );
        let journaled = journal_record(
            ctx,
            req,
            "security.baselineAccept",
            &summary,
            Some(&format!("gen{number}")),
        );
        Ok(json!({
            "acceptedGeneration": number,
            "fileCount": candidate.file_count,
            "acceptedAtUnixSecs": index.accepted_at_unix_secs,
            "journalRecorded": journaled,
        }))
    })
}

/// Explicit removal of stored generations.
pub fn prune(ctx: &Context<'_>, req: &Request) -> Result<Value, Error> {
    let mode = req.mode.expect("validated by the request");
    mutate(ctx, req, |store, _target| {
        let mut index = load_index(store)?;
        let before = index.generations.len();
        let keep: Vec<u32> = match mode {
            PruneMode::All => vec![],
            PruneMode::Candidate => index
                .generations
                .iter()
                .copied()
                .filter(|g| Some(*g) != index.candidate)
                .collect(),
            PruneMode::Superseded => index
                .generations
                .iter()
                .copied()
                .filter(|g| Some(*g) == index.accepted || Some(*g) == index.candidate)
                .collect(),
        };
        for generation in index
            .generations
            .iter()
            .copied()
            .filter(|g| !keep.contains(g))
        {
            store.remove_generation(generation);
        }
        index.generations = keep;
        if mode == PruneMode::All {
            index.accepted = None;
            index.accepted_at_unix_secs = None;
        }
        if mode == PruneMode::All || mode == PruneMode::Candidate {
            index.candidate = None;
        }
        store.save_index(&index).map_err(Error::Io)?;
        store.sweep(&index);
        let removed = before - index.generations.len();
        let summary = format!("pruned {removed} generations");
        let journaled = journal_record(ctx, req, "security.baselinePrune", &summary, None);
        Ok(json!({
            "removed": removed,
            "acceptedGeneration": index.accepted,
            "candidateGeneration": index.candidate,
            "journalRecorded": journaled,
        }))
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;

    const SITE: &str = "123e4567-e89b-12d3-a456-426614174000";

    struct Fixture {
        state_dir: tempfile::TempDir,
        site_dir: tempfile::TempDir,
        counter: std::cell::Cell<u32>,
    }

    impl Fixture {
        fn new() -> Self {
            let f = Self {
                state_dir: tempfile::tempdir().unwrap(),
                site_dir: tempfile::tempdir().unwrap(),
                counter: std::cell::Cell::new(0),
            };
            f.put("index.php", "<?php echo 1;");
            f.put("wp-content/plugins/a/a.php", "<?php // a");
            f.put("wp-content/uploads/x.php", "ignored");
            f
        }

        fn put(&self, rel: &str, body: &str) {
            let path = self.site_dir.path().join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
        }

        fn id(&self) -> String {
            self.counter.set(self.counter.get() + 1);
            format!(
                "123e4567-e89b-12d3-a456-4266141740{:02}",
                self.counter.get()
            )
        }

        fn root(&self) -> String {
            self.site_dir
                .path()
                .canonicalize()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        }

        fn state(&self) -> ManagedRoot {
            ManagedRoot::open(&TrustedRoot::parse(self.state_dir.path()).unwrap()).unwrap()
        }

        fn run(&self, op: Op, extra: &str) -> Result<Value, Error> {
            self.run_with(op, extra, Limits::DEFAULT)
        }

        fn run_with(&self, op: Op, extra: &str, limits: Limits) -> Result<Value, Error> {
            let kind = if op == Op::Prune {
                String::new()
            } else {
                r#","kind":"wordpress""#.into()
            };
            let actor = if op == Op::Compare {
                ""
            } else {
                r#","actor":"user:1""#
            };
            let json = format!(
                r#"{{"siteId":"{SITE}","projectRoot":"{}"{kind}{actor}{extra}}}"#,
                self.root()
            );
            let request = Request::parse(op, &json, &self.id(), None).unwrap();
            let state = self.state();
            let ctx = Context {
                engine_state: &state,
                content_roots: vec![self.site_dir.path().canonicalize().unwrap()],
                limits,
            };
            match op {
                Op::Capture => capture(&ctx, &request),
                Op::Compare => compare(&ctx, &request),
                Op::Accept => accept(&ctx, &request),
                Op::Prune => prune(&ctx, &request),
            }
        }

        fn capture_and_accept(&self) -> Value {
            let captured = self.run(Op::Capture, "").unwrap();
            let extra = format!(
                r#","generation":{},"digest":"{}""#,
                captured["generation"],
                captured["digest"].as_str().unwrap()
            );
            self.run(Op::Accept, &extra).unwrap();
            captured
        }

        fn snapshot(&self) -> Vec<(String, Vec<u8>)> {
            let mut out = vec![];
            let mut stack = vec![self.site_dir.path().to_path_buf()];
            while let Some(dir) = stack.pop() {
                for entry in fs::read_dir(dir).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        stack.push(path);
                    } else {
                        out.push((path.display().to_string(), fs::read(&path).unwrap()));
                    }
                }
            }
            out.sort();
            out
        }
    }

    #[test]
    fn no_baseline_then_capture_accept_match() {
        let f = Fixture::new();
        assert_eq!(f.run(Op::Compare, "").unwrap()["status"], "noBaseline");
        let before = f.snapshot();
        let captured = f.run(Op::Capture, "").unwrap();
        assert_eq!(captured["complete"], true);
        assert_eq!(captured["fileCount"], 2);
        // Still no accepted baseline: capture only wrote a candidate.
        let status = f.run(Op::Compare, "").unwrap();
        assert_eq!(status["status"], "noBaseline");
        assert_eq!(status["candidateGeneration"], 1);
        f.capture_and_accept();
        let same = f.run(Op::Compare, "").unwrap();
        assert_eq!(same["status"], "match");
        assert_eq!(same["filesScanned"], 2);
        // Neither capture, accept nor compare touched the site.
        assert_eq!(f.snapshot(), before);
    }

    #[test]
    fn changed_added_and_deleted_files_are_listed() {
        let f = Fixture::new();
        f.capture_and_accept();
        f.put("index.php", "<?php evil();");
        f.put("wp-content/plugins/a/new.php", "x");
        fs::remove_file(f.site_dir.path().join("wp-content/plugins/a/a.php")).unwrap();
        f.put("wp-content/uploads/more.php", "excluded, no signal");
        let result = f.run(Op::Compare, "").unwrap();
        assert_eq!(result["status"], "differs");
        assert_eq!(result["changedPaths"], json!(["index.php"]));
        assert_eq!(
            result["addedPaths"],
            json!(["wp-content/plugins/a/new.php"])
        );
        assert_eq!(
            result["deletedPaths"],
            json!(["wp-content/plugins/a/a.php"])
        );
    }

    #[test]
    fn capture_never_replaces_the_accepted_generation() {
        let f = Fixture::new();
        f.capture_and_accept();
        f.put("index.php", "<?php changed();");
        let candidate = f.run(Op::Capture, "").unwrap();
        assert_eq!(candidate["generation"], 2);
        assert_eq!(candidate["acceptedGeneration"], 1);
        assert_eq!(candidate["diffFromAccepted"]["changed"], 1);
        // The old code is still the reference: the change still shows.
        assert_eq!(f.run(Op::Compare, "").unwrap()["status"], "differs");
    }

    #[test]
    fn accept_refuses_changed_code_wrong_digest_and_wrong_generation() {
        let f = Fixture::new();
        let captured = f.run(Op::Capture, "").unwrap();
        let generation = captured["generation"].clone();
        let digest = captured["digest"].as_str().unwrap().to_owned();
        let bad_digest = "0".repeat(64);
        assert!(matches!(
            f.run(
                Op::Accept,
                &format!(r#","generation":{generation},"digest":"{bad_digest}""#)
            ),
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            f.run(
                Op::Accept,
                &format!(r#","generation":9,"digest":"{digest}""#)
            ),
            Err(Error::Invalid(_))
        ));
        f.put("index.php", "<?php changed after capture");
        assert!(matches!(
            f.run(
                Op::Accept,
                &format!(r#","generation":{generation},"digest":"{digest}""#)
            ),
            Err(Error::Conflict(_))
        ));
        assert_eq!(f.run(Op::Compare, "").unwrap()["status"], "noBaseline");
    }

    #[test]
    fn unreadable_code_is_incomplete_and_cannot_be_accepted() {
        let f = Fixture::new();
        let fifo =
            std::ffi::CString::new(f.site_dir.path().join("pipe.php").to_str().unwrap()).unwrap();
        // SAFETY: valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let captured = f.run(Op::Capture, "").unwrap();
        assert_eq!(captured["complete"], false);
        assert_eq!(captured["incompleteReason"], "unreadable");
        assert_eq!(captured["stoppedAt"], "pipe.php");
        let digest = captured["digest"].as_str().unwrap();
        assert!(matches!(
            f.run(
                Op::Accept,
                &format!(r#","generation":1,"digest":"{digest}""#)
            ),
            Err(Error::Invalid(_))
        ));
        fs::remove_file(f.site_dir.path().join("pipe.php")).unwrap();
        f.capture_and_accept();
        let fifo =
            std::ffi::CString::new(f.site_dir.path().join("pipe.php").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let result = f.run(Op::Compare, "").unwrap();
        assert_eq!(result["status"], "incomplete");
        assert_eq!(result["reason"], "unreadable");
    }

    #[test]
    fn a_limit_is_incomplete_not_a_match() {
        let f = Fixture::new();
        f.capture_and_accept();
        let tiny = Limits {
            max_files: 1,
            ..Limits::DEFAULT
        };
        let result = f.run_with(Op::Compare, "", tiny).unwrap();
        assert_eq!(result["status"], "incomplete");
        assert_eq!(result["reason"], "fileLimit");
    }

    #[test]
    fn a_corrupt_baseline_is_unavailable() {
        let f = Fixture::new();
        f.capture_and_accept();
        let index = f
            .state_dir
            .path()
            .join(format!("security-baselines/{SITE}/index.json"));
        fs::write(index, "{").unwrap();
        let result = f.run(Op::Compare, "").unwrap();
        assert_eq!(result["status"], "unavailable");
        let gen_file = f
            .state_dir
            .path()
            .join(format!("security-baselines/{SITE}/gen-000001.json"));
        assert!(gen_file.exists());
    }

    #[test]
    fn a_held_project_lock_gives_conflict() {
        let f = Fixture::new();
        let state = f.state();
        let _held = resource_lock::acquire(
            &state,
            Path::new(&f.root()),
            RequestId::parse("123e4567-e89b-12d3-a456-426614174099").unwrap(),
        )
        .unwrap();
        assert!(matches!(f.run(Op::Compare, ""), Err(Error::ResourceBusy)));
        assert!(matches!(f.run(Op::Capture, ""), Err(Error::ResourceBusy)));
    }

    #[test]
    fn retention_keeps_three_generations_and_prune_removes() {
        let f = Fixture::new();
        for round in 0..5 {
            f.put("index.php", &format!("<?php // {round}"));
            f.capture_and_accept();
        }
        let dir = f
            .state_dir
            .path()
            .join(format!("security-baselines/{SITE}"));
        let gens = |dir: &Path| {
            let mut names: Vec<String> = fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .filter(|n| n.starts_with("gen-"))
                .collect();
            names.sort();
            names
        };
        assert_eq!(
            gens(&dir),
            ["gen-000003.json", "gen-000004.json", "gen-000005.json"]
        );
        assert_eq!(f.run(Op::Compare, "").unwrap()["generation"], 5);
        // An older stored generation can be compared on request (rollback review).
        assert_eq!(
            f.run(Op::Compare, r#","generation":4"#).unwrap()["status"],
            "differs"
        );
        let pruned = f.run(Op::Prune, r#","mode":"superseded""#).unwrap();
        assert_eq!(pruned["removed"], 2);
        assert_eq!(gens(&dir), ["gen-000005.json"]);
        f.run(Op::Prune, r#","mode":"all""#).unwrap();
        assert!(gens(&dir).is_empty());
        assert_eq!(f.run(Op::Compare, "").unwrap()["status"], "noBaseline");
    }

    #[test]
    fn accept_and_prune_are_journaled_without_content() {
        let f = Fixture::new();
        f.capture_and_accept();
        f.run(Op::Prune, r#","mode":"all""#).unwrap();
        let journal = fs::read_to_string(f.state_dir.path().join("journal/events.jsonl")).unwrap();
        assert!(journal.contains("security.baselineAccept"));
        assert!(journal.contains("security.baselinePrune"));
        assert!(journal.contains("user:1"));
        assert!(!journal.contains("index.php"));
    }

    #[test]
    fn root_changes_make_the_baseline_incomparable() {
        let f = Fixture::new();
        f.capture_and_accept();
        // Same site id and request shape, another project root.
        let other = tempfile::tempdir().unwrap();
        fs::write(other.path().join("index.php"), "x").unwrap();
        let json = format!(
            r#"{{"siteId":"{SITE}","projectRoot":"{}","kind":"wordpress"}}"#,
            other.path().canonicalize().unwrap().display()
        );
        let request = Request::parse(Op::Compare, &json, &f.id(), None).unwrap();
        let state = f.state();
        let ctx = Context {
            engine_state: &state,
            content_roots: vec![other.path().canonicalize().unwrap()],
            limits: Limits::DEFAULT,
        };
        let result = compare(&ctx, &request).unwrap();
        assert_eq!(result["status"], "unavailable");
        assert_eq!(result["reason"], "rootChanged");
        // A different kind is a different scope.
        let json = format!(
            r#"{{"siteId":"{SITE}","projectRoot":"{}","kind":"drupal"}}"#,
            f.root()
        );
        let request = Request::parse(Op::Compare, &json, &f.id(), None).unwrap();
        let ctx = Context {
            engine_state: &state,
            content_roots: vec![f.site_dir.path().canonicalize().unwrap()],
            limits: Limits::DEFAULT,
        };
        assert_eq!(compare(&ctx, &request).unwrap()["reason"], "scopeChanged");
    }

    #[test]
    fn a_root_outside_the_content_roots_is_refused() {
        let f = Fixture::new();
        let state = f.state();
        let json = format!(
            r#"{{"siteId":"{SITE}","projectRoot":"{}","kind":"wordpress"}}"#,
            f.root()
        );
        let request = Request::parse(Op::Compare, &json, &f.id(), None).unwrap();
        let ctx = Context {
            engine_state: &state,
            content_roots: vec![PathBuf::from("/var/www")],
            limits: Limits::DEFAULT,
        };
        assert!(matches!(compare(&ctx, &request), Err(Error::Root(_))));
    }

    #[test]
    fn request_validation() {
        let id = "123e4567-e89b-12d3-a456-426614174000";
        let base = |extra: &str| {
            format!(
                r#"{{"siteId":"{SITE}","projectRoot":"/var/www/a","kind":"wordpress","actor":"user:1"{extra}}}"#
            )
        };
        assert!(Request::parse(Op::Capture, &base(""), id, None).is_ok());
        for (op, extra) in [
            (Op::Capture, r#","generation":1"#),
            (Op::Capture, r#","digest":"x""#),
            (Op::Capture, r#","mode":"all""#),
            (Op::Accept, ""),
            (Op::Accept, r#","generation":1,"digest":"abc""#),
            (
                Op::Accept,
                r#","generation":0,"digest":"0000000000000000000000000000000000000000000000000000000000000000""#,
            ),
            (Op::Capture, r#","unknown":1"#),
            (Op::Capture, r#","subsite":"a/b""#),
        ] {
            assert!(
                Request::parse(op, &base(extra), id, None).is_err(),
                "{extra}"
            );
        }
        assert!(
            Request::parse(
                Op::Capture,
                &base("").replace("wordpress", "typo3"),
                id,
                None
            )
            .is_err()
        );
        assert!(
            Request::parse(
                Op::Capture,
                &base("").replace("/var/www/a", "../x"),
                id,
                None
            )
            .is_err()
        );
        assert!(
            Request::parse(Op::Compare, &base(""), id, None).is_err(),
            "compare has no actor"
        );
        let prune = format!(
            r#"{{"siteId":"{SITE}","projectRoot":"/var/www/a","actor":"u","mode":"bogus"}}"#
        );
        assert!(Request::parse(Op::Prune, &prune, id, None).is_err());
    }
}
