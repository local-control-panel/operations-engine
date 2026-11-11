//! `system.updatesApply`: installs the pending apt upgrades of an explicit list
//! of packages (`apt-get install --only-upgrade`) under one lock/idempotency/
//! transaction/audit-backed request. There is no "upgrade everything": the
//! caller names the packages.
//!
//! Before anything is installed, `apt-get -s install --only-upgrade` is
//! simulated and the request is refused (`INVALID_INPUT`) when a named package
//! is not among the pending upgrades, is a Docker package (those are updated
//! through the managed services), or when the simulation would remove a
//! package or install one that `system.updatesStatus` does not list as pending.
//! Nothing is rebooted; `needrestart` only lists (`NEEDRESTART_MODE=l`) and
//! `reboot` reports whether a restart is now pending (`unknown` when it cannot
//! be read, never "not required").

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessOutput, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::SiteRelativePath,
    system_install_docker,
    system_updates_status::{self, Pending, Reboot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "system.updatesApply";
pub const MAX_PACKAGES: usize = 100;
const SIMULATE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
/// Docker packages beyond the ones `system.installDocker` owns or replaces.
const EXTRA_DOCKER_PACKAGES: &[&str] = &["docker-ce-rootless-extras"];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    packages: Vec<String>,
}

pub struct Request {
    packages: Vec<String>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    NoPackages,
    TooManyPackages,
    InvalidPackageName,
    DuplicatePackage,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

/// Debian package names: lowercase-safe characters, starting with a letter or
/// digit (so a name can never be read as an option), no architecture suffix
/// and no apt pattern characters.
fn name_ok(name: &str) -> bool {
    system_updates_status::package_name_ok(name)
        && !name.contains(':')
        && name.as_bytes()[0].is_ascii_alphanumeric()
}

pub fn is_docker_package(name: &str) -> bool {
    system_install_docker::PACKAGES
        .iter()
        .chain(system_install_docker::FOREIGN_PACKAGES)
        .chain(EXTRA_DOCKER_PACKAGES)
        .any(|docker| *docker == name)
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.packages.is_empty() {
            return Err(RequestError::NoPackages);
        }
        if plan.packages.len() > MAX_PACKAGES {
            return Err(RequestError::TooManyPackages);
        }
        let mut seen = BTreeSet::new();
        for name in &plan.packages {
            if !name_ok(name) {
                return Err(RequestError::InvalidPackageName);
            }
            if !seen.insert(name.as_str()) {
                return Err(RequestError::DuplicatePackage);
            }
        }
        Ok(Self {
            packages: plan.packages,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Simulate,
    Install,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::Simulate => "could not simulate the package upgrade",
            Self::Install => "could not install the package upgrades",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum PackageOutcome {
    /// The installed version changed.
    Upgraded,
    /// The installed version is the same as before.
    Unchanged,
    /// The installed version could not be read before or after.
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PackageResult {
    pub name: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub outcome: PackageOutcome,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Completion {
    /// `apt-get` finished successfully.
    Complete,
    /// `apt-get` failed after some packages had already changed.
    Partial,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyResult {
    pub completion: Completion,
    pub packages: Vec<PackageResult>,
    pub reboot: Reboot,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub apt_get_program: &'a str,
    pub dpkg_query_program: &'a str,
    /// Where pending upgrades and `reboot-required` are read from; its
    /// `apt_get` should be `apt_get_program`.
    pub status: system_updates_status::Context<'a>,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Invalid(String),
    PendingUnknown,
    Busy,
    Run(Stage, process::ProcessRunError),
    Rejected(Stage, SubprocessDiagnostics),
    PostCommit { result: ApplyResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another package update is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Busy => (
                ErrorCode::Conflict,
                "apt or dpkg is in use by another process".into(),
            ),
            Self::Invalid(message) => (ErrorCode::InvalidInput, message.clone()),
            Self::PendingUnknown => (
                ErrorCode::SubprocessFailed,
                "could not determine the pending package upgrades".into(),
            ),
            Self::Run(stage, error) => (process::spawn_error_code(error), stage.message().into()),
            Self::Rejected(stage, diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                stage.message().into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal package update error".into())
            }
        }
    }
}

fn succeeded(output: &ProcessOutput) -> bool {
    matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    )
}

/// A held apt/dpkg lock is a conflict the caller can retry, not a failure.
fn lock_held(output: &ProcessOutput) -> bool {
    let text = String::from_utf8_lossy(&output.stderr.bytes);
    text.contains("Could not get lock")
        || text.contains("Unable to acquire the dpkg frontend lock")
        || text.contains("Unable to lock directory")
}

fn apt_request(ctx: &Context<'_>, args: &[&str]) -> ProcessRequest {
    ProcessRequest::new(ctx.apt_get_program)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("NEEDRESTART_MODE", "l")
        .env("LC_ALL", "C")
}

/// What `apt-get -s` says it would do, by package name.
#[derive(Debug, Default, Eq, PartialEq)]
struct Simulation {
    installs: Vec<String>,
    removals: Vec<String>,
}

fn parse_simulation(text: &str) -> Simulation {
    let mut sim = Simulation::default();
    for line in text.lines() {
        let (kind, rest) = match line.split_once(' ') {
            Some(parts) => parts,
            None => continue,
        };
        let name = rest.split(' ').next().unwrap_or_default().to_string();
        match kind {
            "Inst" => sim.installs.push(name),
            "Remv" | "Purg" => sim.removals.push(name),
            _ => {}
        }
    }
    sim
}

fn simulate(
    ctx: &Context<'_>,
    packages: &[String],
    cancel: &CancellationToken,
) -> Result<Simulation, Error> {
    let mut args = vec![
        "-s",
        "-o",
        "Debug::NoLocking=1",
        "install",
        "--only-upgrade",
    ];
    args.extend(packages.iter().map(String::as_str));
    let output = process::run(
        &apt_request(ctx, &args),
        &ProcessLimits {
            timeout: SIMULATE_TIMEOUT,
            max_stdout_bytes: 4 * 1024 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        cancel,
    )
    .map_err(|e| Error::Run(Stage::Simulate, e))?;
    if !succeeded(&output) || output.stdout.truncated {
        return Err(Error::Rejected(
            Stage::Simulate,
            SubprocessDiagnostics::from_output(ctx.apt_get_program, &output),
        ));
    }
    Ok(parse_simulation(&String::from_utf8_lossy(
        &output.stdout.bytes,
    )))
}

/// Refuses anything but upgrades of packages `system.updatesStatus` lists.
fn check_plan(ctx: &Context<'_>, req: &Request, cancel: &CancellationToken) -> Result<(), Error> {
    if let Some(name) = req.packages.iter().find(|n| is_docker_package(n)) {
        return Err(Error::Invalid(format!(
            "{name} is a Docker package; it is updated through the managed services"
        )));
    }
    let Pending::Known {
        packages: pending,
        truncated,
    } = system_updates_status::pending(&ctx.status, cancel)
    else {
        return Err(Error::PendingUnknown);
    };
    for name in &req.packages {
        let upgradable = pending
            .iter()
            .any(|p| &p.name == name && p.installed.is_some());
        if !upgradable {
            return Err(Error::Invalid(format!("{name} is not a pending upgrade")));
        }
    }
    let sim = simulate(ctx, &req.packages, cancel)?;
    if let Some(name) = sim.removals.first() {
        return Err(Error::Invalid(format!(
            "upgrading would remove {name}; refused"
        )));
    }
    for name in &sim.installs {
        if is_docker_package(name) {
            return Err(Error::Invalid(format!(
                "upgrading would also change the Docker package {name}; refused"
            )));
        }
        let wanted = req.packages.contains(name);
        let dependency = pending.iter().any(|p| &p.name == name);
        if !wanted && !dependency {
            return Err(Error::Invalid(if truncated {
                format!("{name} would be installed and could not be matched to a pending upgrade")
            } else {
                format!("upgrading would install {name}, which is not a pending upgrade")
            }));
        }
    }
    Ok(())
}

fn installed_version(ctx: &Context<'_>, name: &str, cancel: &CancellationToken) -> Option<String> {
    let output = process::run(
        &ProcessRequest::new(ctx.dpkg_query_program)
            .args(["-W", "-f=${Version}", name])
            .env("LC_ALL", "C"),
        &ProcessLimits {
            timeout: QUERY_TIMEOUT,
            max_stdout_bytes: 4 * 1024,
            max_stderr_bytes: 4 * 1024,
        },
        cancel,
    )
    .ok()?;
    if !succeeded(&output) || output.stdout.truncated {
        return None;
    }
    let version = String::from_utf8(output.stdout.bytes).ok()?;
    let version = version.trim();
    (!version.is_empty() && version.len() <= 128 && !version.contains(char::is_whitespace))
        .then(|| version.to_string())
}

fn versions(
    ctx: &Context<'_>,
    packages: &[String],
    cancel: &CancellationToken,
) -> Vec<Option<String>> {
    packages
        .iter()
        .map(|name| installed_version(ctx, name, cancel))
        .collect()
}

fn install(
    ctx: &Context<'_>,
    packages: &[String],
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let mut args = vec![
        "install",
        "--only-upgrade",
        "-y",
        "-o",
        "Dpkg::Options::=--force-confold",
    ];
    args.extend(packages.iter().map(String::as_str));
    let output = process::run(
        &apt_request(ctx, &args),
        &ProcessLimits {
            timeout: INSTALL_TIMEOUT,
            max_stdout_bytes: 256 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        cancel,
    )
    .map_err(|e| Error::Run(Stage::Install, e))?;
    if succeeded(&output) {
        return Ok(());
    }
    if lock_held(&output) {
        return Err(Error::Busy);
    }
    Err(Error::Rejected(
        Stage::Install,
        SubprocessDiagnostics::from_output(ctx.apt_get_program, &output),
    ))
}

fn results(
    packages: &[String],
    before: Vec<Option<String>>,
    after: Vec<Option<String>>,
) -> Vec<PackageResult> {
    packages
        .iter()
        .zip(before)
        .zip(after)
        .map(|((name, before), after)| {
            let outcome = match (&before, &after) {
                (Some(b), Some(a)) if a != b => PackageOutcome::Upgraded,
                (Some(_), Some(_)) => PackageOutcome::Unchanged,
                _ => PackageOutcome::Unknown,
            };
            PackageResult {
                name: name.clone(),
                before,
                after,
                outcome,
            }
        })
        .collect()
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<ApplyResult, Error> {
    let scope_path = SiteRelativePath::parse("system-updates-apply").unwrap();
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
    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();

    if let Err(error) = check_plan(ctx, req, cancel) {
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }
    let before = versions(ctx, &req.packages, cancel);
    let install_error = install(ctx, &req.packages, cancel).err();
    let after = versions(ctx, &req.packages, cancel);
    let packages = results(&req.packages, before, after);
    let completion = match install_error {
        None => Completion::Complete,
        Some(error)
            if packages
                .iter()
                .any(|p| p.outcome == PackageOutcome::Upgraded) =>
        {
            drop(error);
            Completion::Partial
        }
        Some(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };

    let result = ApplyResult {
        completion,
        packages,
        reboot: system_updates_status::reboot(&ctx.status),
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<ApplyResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| Error::Io(std::io::Error::other(error)))
        }
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    scope: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, state_path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn managed(directory: &Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    fn script(path: &Path, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// A fake host under one directory:
    /// - `dist.txt`: output of the `dist-upgrade` simulation (pending set);
    /// - `sim.txt`: output of the `install --only-upgrade` simulation;
    /// - `versions/<pkg>`: installed versions; `after/<pkg>` replaces them
    ///   when a real install runs;
    /// - `install-exit` / `install-stderr`: how the real install ends;
    /// - `calls.log`: one argv line per apt call, with the NEEDRESTART mode.
    struct Host {
        dir: tempfile::TempDir,
        apt: String,
        dpkg: String,
        reboot_required: std::path::PathBuf,
        reboot_required_pkgs: std::path::PathBuf,
    }

    impl Host {
        fn new(pending: &[(&str, &str, &str)]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            fs::create_dir_all(root.join("versions")).unwrap();
            fs::create_dir_all(root.join("after")).unwrap();
            let mut dist = String::new();
            for (name, old, new) in pending {
                dist.push_str(&format!(
                    "Inst {name} [{old}] ({new} Ubuntu:24.04/noble-updates [amd64])\n"
                ));
                fs::write(root.join("versions").join(name), old).unwrap();
                fs::write(root.join("after").join(name), new).unwrap();
            }
            fs::write(root.join("dist.txt"), &dist).unwrap();
            fs::write(root.join("sim.txt"), &dist).unwrap();
            fs::write(root.join("install-exit"), "0").unwrap();
            let d = root.display();
            let apt = script(
                &root.join("fake-apt-get"),
                &format!(
                    "D='{d}'\necho \"$NEEDRESTART_MODE $*\" >> \"$D/calls.log\"\n\
case \"$*\" in\n\
  *dist-upgrade*) cat \"$D/dist.txt\"; exit 0;;\n\
  *\"-s \"*install*) cat \"$D/sim.txt\"; exit 0;;\n\
esac\n\
[ -f \"$D/install-stderr\" ] && cat \"$D/install-stderr\" >&2\n\
if [ -f \"$D/partial\" ]; then for f in $(cat \"$D/partial\"); do cp \"$D/after/$f\" \"$D/versions/$f\"; done; \
else [ \"$(cat \"$D/install-exit\")\" = 0 ] && cp \"$D\"/after/* \"$D/versions/\"; fi\n\
exit \"$(cat \"$D/install-exit\")\"\n"
                ),
            );
            let dpkg = script(
                &root.join("fake-dpkg-query"),
                &format!("for last; do :; done\ncat '{d}/versions/'\"$last\" 2>/dev/null\n"),
            );
            Self {
                reboot_required: root.join("reboot-required"),
                reboot_required_pkgs: root.join("reboot-required.pkgs"),
                dir,
                apt,
                dpkg,
            }
        }

        fn path(&self, name: &str) -> std::path::PathBuf {
            self.dir.path().join(name)
        }

        fn calls(&self) -> Vec<String> {
            fs::read_to_string(self.path("calls.log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }

        fn real_installs(&self) -> usize {
            self.calls()
                .iter()
                .filter(|c| c.contains(" install ") && !c.contains(" -s "))
                .count()
        }

        fn ctx<'a>(&'a self, state: &'a ManagedRoot) -> Context<'a> {
            Context {
                engine_state: state,
                apt_get_program: &self.apt,
                dpkg_query_program: &self.dpkg,
                status: system_updates_status::Context {
                    apt_get: &self.apt,
                    reboot_required: &self.reboot_required,
                    reboot_required_pkgs: &self.reboot_required_pkgs,
                    update_stamp: Path::new("/nonexistent/stamp"),
                    apt_history: Path::new("/nonexistent/history"),
                },
            }
        }
    }

    fn request(packages: &[&str], key: Option<&str>) -> Request {
        let json = serde_json::json!({ "packages": packages }).to_string();
        Request::parse(&json, ID, key).unwrap()
    }

    fn run(host: &Host, req: &Request) -> Result<ApplyResult, Error> {
        let state_dir = tempfile::tempdir().unwrap();
        let state = managed(state_dir.path());
        execute(&host.ctx(&state), req, &CancellationToken::default())
    }

    #[test]
    fn parses_a_valid_request_and_rejects_each_bad_field() {
        let ok = |json: &str| Request::parse(json, ID, None).map(|_| ());
        assert!(ok(r#"{"packages":["libc6","openssl"]}"#).is_ok());
        assert_eq!(ok("{"), Err(RequestError::InvalidJson));
        assert_eq!(
            ok(r#"{"packages":["a"],"extra":1}"#),
            Err(RequestError::InvalidJson)
        );
        assert_eq!(ok(r#"{}"#), Err(RequestError::InvalidJson));
        assert_eq!(ok(r#"{"packages":[]}"#), Err(RequestError::NoPackages));
        for bad in [
            "libc6:amd64",
            "lib*",
            "lib?",
            "-y",
            "",
            "a b",
            "a;b",
            "../x",
        ] {
            assert_eq!(
                ok(&serde_json::json!({ "packages": [bad] }).to_string()),
                Err(RequestError::InvalidPackageName),
                "{bad}"
            );
        }
        assert_eq!(
            ok(r#"{"packages":["curl","curl"]}"#),
            Err(RequestError::DuplicatePackage)
        );
        let many: Vec<String> = (0..=MAX_PACKAGES).map(|i| format!("pkg{i}")).collect();
        assert_eq!(
            ok(&serde_json::json!({ "packages": many }).to_string()),
            Err(RequestError::TooManyPackages)
        );
        assert_eq!(
            Request::parse(r#"{"packages":["a"]}"#, "nope", None).err(),
            Some(RequestError::InvalidRequestId)
        );
        assert_eq!(
            Request::parse(r#"{"packages":["a"]}"#, ID, Some("bad key")).err(),
            Some(RequestError::InvalidIdempotencyKey)
        );
    }

    #[test]
    fn simulates_before_installing_and_reports_versions_per_package() {
        let host = Host::new(&[("curl", "8.5.0-1", "8.5.0-2"), ("tzdata", "2024a", "2024b")]);
        let result = run(&host, &request(&["curl"], None)).unwrap();

        assert_eq!(result.completion, Completion::Complete);
        assert_eq!(
            result.packages,
            [PackageResult {
                name: "curl".into(),
                before: Some("8.5.0-1".into()),
                after: Some("8.5.0-2".into()),
                outcome: PackageOutcome::Upgraded,
            }]
        );
        let calls = host.calls();
        let sim = calls
            .iter()
            .position(|c| c.contains(" -s ") && c.contains("install"))
            .unwrap();
        let real = calls
            .iter()
            .position(|c| c.contains("install --only-upgrade -y"))
            .unwrap();
        assert!(sim < real, "{calls:?}");
        assert!(
            calls[real].starts_with("l "),
            "needrestart must only list: {calls:?}"
        );
        assert!(calls[real].ends_with("-o Dpkg::Options::=--force-confold curl"));
        assert_eq!(result.reboot, Reboot::NotRequired);
    }

    #[test]
    fn reports_a_pending_reboot_but_never_reboots() {
        let host = Host::new(&[("libc6", "1", "2")]);
        fs::write(host.path("reboot-required"), "").unwrap();
        fs::write(host.path("reboot-required.pkgs"), "libc6\n").unwrap();
        let result = run(&host, &request(&["libc6"], None)).unwrap();
        assert_eq!(
            result.reboot,
            Reboot::Required {
                packages: vec!["libc6".into()]
            }
        );
        assert!(host.calls().iter().all(|c| !c.contains("reboot")));
    }

    #[test]
    fn refuses_a_package_that_is_not_a_pending_upgrade() {
        let host = Host::new(&[("curl", "1", "2")]);
        let error = run(&host, &request(&["vim"], None)).unwrap_err();
        assert!(
            matches!(&error, Error::Invalid(m) if m.contains("vim")),
            "{error:?}"
        );
        assert_eq!(error.protocol().0, ErrorCode::InvalidInput);
        assert_eq!(host.real_installs(), 0);
    }

    #[test]
    fn refuses_a_new_package_even_when_apt_would_install_it() {
        let host = Host::new(&[("curl", "1", "2")]);
        // Listed by dist-upgrade as a new install (no installed version).
        fs::write(
            host.path("dist.txt"),
            "Inst curl [1] (2 x [amd64])\nInst extra (1 x [amd64])\n",
        )
        .unwrap();
        let error = run(&host, &request(&["extra"], None)).unwrap_err();
        assert!(matches!(error, Error::Invalid(_)), "{error:?}");
        assert_eq!(host.real_installs(), 0);
    }

    #[test]
    fn refuses_docker_packages_before_running_apt() {
        let host = Host::new(&[("docker-ce", "1", "2"), ("curl", "1", "2")]);
        for name in [
            "docker-ce",
            "docker-ce-cli",
            "docker.io",
            "containerd",
            "containerd.io",
            "runc",
            "docker-compose-plugin",
            "docker-buildx-plugin",
        ] {
            let error = run(&host, &request(&["curl", name], None)).unwrap_err();
            assert!(
                matches!(&error, Error::Invalid(m) if m.contains(name)),
                "{name}"
            );
        }
        assert!(host.calls().is_empty());
    }

    #[test]
    fn refuses_when_the_simulation_would_change_a_docker_package() {
        let host = Host::new(&[("curl", "1", "2"), ("containerd.io", "1", "2")]);
        fs::write(
            host.path("sim.txt"),
            "Inst curl [1] (2 x [amd64])\nInst containerd.io [1] (2 x [amd64])\n",
        )
        .unwrap();
        let error = run(&host, &request(&["curl"], None)).unwrap_err();
        assert!(matches!(&error, Error::Invalid(m) if m.contains("containerd.io")));
        assert_eq!(host.real_installs(), 0);
    }

    #[test]
    fn refuses_when_the_simulation_would_remove_a_package() {
        let host = Host::new(&[("curl", "1", "2")]);
        fs::write(
            host.path("sim.txt"),
            "Inst curl [1] (2 x [amd64])\nRemv libold [1]\n",
        )
        .unwrap();
        let error = run(&host, &request(&["curl"], None)).unwrap_err();
        assert!(
            matches!(&error, Error::Invalid(m) if m.contains("libold")),
            "{error:?}"
        );
        assert_eq!(host.real_installs(), 0);
    }

    #[test]
    fn refuses_a_new_package_that_is_not_a_pending_dependency() {
        let host = Host::new(&[("curl", "1", "2")]);
        fs::write(
            host.path("sim.txt"),
            "Inst curl [1] (2 x [amd64])\nInst surprise (1 x [amd64])\n",
        )
        .unwrap();
        let error = run(&host, &request(&["curl"], None)).unwrap_err();
        assert!(
            matches!(&error, Error::Invalid(m) if m.contains("surprise")),
            "{error:?}"
        );
        assert_eq!(host.real_installs(), 0);
    }

    #[test]
    fn allows_a_new_package_that_is_a_dependency_of_a_pending_upgrade() {
        let host = Host::new(&[("linux-image", "1", "2")]);
        fs::write(
            host.path("dist.txt"),
            "Inst linux-image [1] (2 x [amd64])\nInst linux-modules (2 x [amd64])\n",
        )
        .unwrap();
        fs::write(
            host.path("sim.txt"),
            fs::read_to_string(host.path("dist.txt")).unwrap(),
        )
        .unwrap();
        let result = run(&host, &request(&["linux-image"], None)).unwrap();
        assert_eq!(result.completion, Completion::Complete);
    }

    #[test]
    fn a_failed_install_fails_the_transaction_and_replays_without_running_apt() {
        let host = Host::new(&[("curl", "1", "2")]);
        fs::write(host.path("install-exit"), "100").unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let state = managed(state_dir.path());
        let ctx = host.ctx(&state);
        let req = request(&["curl"], Some("apply"));

        let first = execute(&ctx, &req, &CancellationToken::default());
        assert!(matches!(first, Err(Error::Rejected(Stage::Install, _))));
        let calls_after_first = host.calls().len();
        let replayed = execute(&ctx, &req, &CancellationToken::default());
        assert!(matches!(
            replayed,
            Err(Error::Replayed {
                code: ErrorCode::SubprocessFailed,
                ..
            })
        ));
        assert_eq!(
            host.calls().len(),
            calls_after_first,
            "a replay must not run apt"
        );
        let record = fs::read_to_string(
            state_dir
                .path()
                .join(format!("system-updates-apply/transactions/{ID}.json")),
        )
        .unwrap();
        assert!(record.contains("\"status\":\"FAILED\""), "{record}");
    }

    #[test]
    fn a_successful_replay_returns_the_recorded_result_without_running_apt() {
        let host = Host::new(&[("curl", "1", "2")]);
        let state_dir = tempfile::tempdir().unwrap();
        let state = managed(state_dir.path());
        let ctx = host.ctx(&state);
        let req = request(&["curl"], Some("apply"));

        let first = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        let calls = host.calls().len();
        let second = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(first.packages, second.packages);
        assert_eq!(host.calls().len(), calls);
        assert_eq!(host.real_installs(), 1);
    }

    #[test]
    fn a_failure_after_some_packages_changed_is_reported_as_partial() {
        let host = Host::new(&[("curl", "1", "2"), ("tzdata", "1", "2")]);
        fs::write(host.path("install-exit"), "100").unwrap();
        fs::write(host.path("partial"), "curl").unwrap();
        let result = run(&host, &request(&["curl", "tzdata"], None)).unwrap();
        assert_eq!(result.completion, Completion::Partial);
        assert_eq!(result.packages[0].outcome, PackageOutcome::Upgraded);
        assert_eq!(result.packages[1].outcome, PackageOutcome::Unchanged);
    }

    #[test]
    fn a_held_apt_lock_is_a_conflict() {
        let host = Host::new(&[("curl", "1", "2")]);
        fs::write(host.path("install-exit"), "100").unwrap();
        fs::write(
            host.path("install-stderr"),
            "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1\n",
        )
        .unwrap();
        let error = run(&host, &request(&["curl"], None)).unwrap_err();
        assert!(matches!(error, Error::Busy));
        assert_eq!(error.protocol().0, ErrorCode::Conflict);
    }

    #[test]
    fn an_unreadable_version_is_unknown_not_unchanged() {
        let host = Host::new(&[("curl", "1", "2")]);
        // dpkg-query cannot answer for this package after the install.
        fs::remove_file(host.path("after/curl")).unwrap();
        fs::write(host.path("install-exit"), "0").unwrap();
        // The fake install copies nothing, then the version file disappears.
        fs::remove_file(host.path("versions/curl")).unwrap();
        let result = run(&host, &request(&["curl"], None)).unwrap();
        assert_eq!(result.packages[0].outcome, PackageOutcome::Unknown);
    }

    #[test]
    fn unknown_pending_upgrades_refuse_the_request() {
        let host = Host::new(&[("curl", "1", "2")]);
        fs::write(
            host.path("fake-apt-get"),
            "#!/bin/sh\necho \"$*\" >> /dev/null\nexit 1\n",
        )
        .unwrap();
        let error = run(&host, &request(&["curl"], None)).unwrap_err();
        assert!(matches!(error, Error::PendingUnknown), "{error:?}");
    }
}
