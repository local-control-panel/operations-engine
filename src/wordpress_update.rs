use crate::{
    db_restore::{ContainerName, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination},
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionStatus},
    },
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "wordpress.updateCore";
pub const PLUGINS_OPERATION: &str = "wordpress.updatePlugins";
pub const THEMES_OPERATION: &str = "wordpress.updateThemes";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    version: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PluginsPlan {
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    plugins: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ThemesPlan {
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    themes: Vec<String>,
}

enum Update {
    Core(Option<String>),
    Plugins(Vec<String>),
    Themes(Vec<String>),
}

pub struct Request {
    container: ContainerName,
    root: PathBuf,
    uid: u32,
    gid: u32,
    update: Update,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug)]
pub struct RequestError;

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError)?;
        let root = PathBuf::from(plan.root);
        if !root.is_absolute()
            || root.as_os_str().len() > 4096
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(RequestError);
        }
        if plan.version.as_deref().is_some_and(|value| {
            value.is_empty()
                || value.len() > 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        }) {
            return Err(RequestError);
        }
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            root,
            uid: plan.uid,
            gid: plan.gid,
            update: Update::Core(plan.version),
            request_id: RequestId::parse(request_id).map_err(|_| RequestError)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError)?,
        })
    }
    pub fn parse_plugins(
        json: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let plan: PluginsPlan = serde_json::from_str(json).map_err(|_| RequestError)?;
        if plan.plugins.len() > 128
            || plan.plugins.iter().any(|slug| {
                slug.is_empty()
                    || slug.len() > 200
                    || !slug.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                    })
            })
        {
            return Err(RequestError);
        }
        let root = PathBuf::from(plan.root);
        if !root.is_absolute()
            || root.as_os_str().len() > 4096
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(RequestError);
        }
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            root,
            uid: plan.uid,
            gid: plan.gid,
            update: Update::Plugins(plan.plugins),
            request_id: RequestId::parse(request_id).map_err(|_| RequestError)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError)?,
        })
    }

    pub fn parse_themes(
        json: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let plan: ThemesPlan = serde_json::from_str(json).map_err(|_| RequestError)?;
        if plan.themes.len() > 128
            || plan.themes.iter().any(|slug| {
                slug.is_empty()
                    || slug.len() > 200
                    || !slug.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                    })
            })
        {
            return Err(RequestError);
        }
        let root = PathBuf::from(plan.root);
        if !root.is_absolute()
            || root.as_os_str().len() > 4096
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(RequestError);
        }
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            root,
            uid: plan.uid,
            gid: plan.gid,
            update: Update::Themes(plan.themes),
            request_id: RequestId::parse(request_id).map_err(|_| RequestError)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError)?,
        })
    }
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateResult {
    pub recovery_id: String,
    pub output: String,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub backup_root: &'a ManagedRoot,
    pub docker_program: &'a str,
    pub tar_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(process::ProcessRunError),
    Rejected(ErrorCode),
    InvalidOutput,
    PostCommit { result: UpdateResult },
    Replayed { code: ErrorCode, message: String },
}
impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another WordPress update is in progress for this site".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run WordPress update prerequisite".into(),
            ),
            Self::Rejected(code) => (*code, "WordPress recovery snapshot or update failed".into()),
            Self::InvalidOutput => (
                ErrorCode::Internal,
                "WordPress update output was invalid".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal WordPress update error".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<UpdateResult, Error> {
    let operation = match req.update {
        Update::Core(_) => OPERATION,
        Update::Plugins(_) => PLUGINS_OPERATION,
        Update::Themes(_) => THEMES_OPERATION,
    };
    let digest = Sha256::digest(req.root.as_os_str().as_encoded_bytes());
    let mut hash = String::new();
    for byte in digest {
        write!(&mut hash, "{byte:02x}").unwrap();
    }
    let scope_path = SiteRelativePath::parse(format!("wordpress-update/{hash}")).unwrap();
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
        operation,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id, operation),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();
    let recovery_dir =
        SiteRelativePath::parse(format!("wordpress-updates/{}", req.request_id)).unwrap();
    ctx.backup_root.create_dir_all(&recovery_dir).map_err(|e| {
        fail(
            &scope,
            &state_path,
            &audit_path,
            state.clone(),
            Error::Io(e),
        )
    })?;
    let files_path =
        SiteRelativePath::parse(format!("{}/files.tar.gz", recovery_dir.as_path().display()))
            .unwrap();
    let db_path =
        SiteRelativePath::parse(format!("{}/database.sql", recovery_dir.as_path().display()))
            .unwrap();
    let files = ctx.backup_root.create_new_file(&files_path).map_err(|e| {
        fail(
            &scope,
            &state_path,
            &audit_path,
            state.clone(),
            Error::Io(e),
        )
    })?;
    run_to_file(
        ProcessRequest::new(ctx.tar_program).args([
            "-C",
            req.root.to_str().unwrap(),
            "-czf",
            "-",
            ".",
        ]),
        files,
        ctx.tar_program,
        cancel,
    )
    .map_err(|e| fail(&scope, &state_path, &audit_path, state.clone(), e))?;
    let database = ctx.backup_root.create_new_file(&db_path).map_err(|e| {
        fail(
            &scope,
            &state_path,
            &audit_path,
            state.clone(),
            Error::Io(e),
        )
    })?;
    run_to_file(
        ProcessRequest::new(ctx.docker_program).args(wp_args(req, ["db", "export", "-"])),
        database,
        ctx.docker_program,
        cancel,
    )
    .map_err(|e| fail(&scope, &state_path, &audit_path, state.clone(), e))?;
    let update = match &req.update {
        Update::Core(version) => {
            let mut args = vec!["core".to_owned(), "update".to_owned()];
            if let Some(version) = version {
                args.push(format!("--version={version}"));
            }
            args
        }
        Update::Plugins(plugins) => {
            let mut args = vec!["plugin".to_owned(), "update".to_owned()];
            if plugins.is_empty() {
                args.push("--all".into());
            } else {
                args.extend(plugins.iter().cloned());
            }
            args
        }
        Update::Themes(themes) => {
            let mut args = vec!["theme".to_owned(), "update".to_owned()];
            if themes.is_empty() {
                args.push("--all".into());
            } else {
                args.extend(themes.iter().cloned());
            }
            args
        }
    };
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(wp_args(req, update)),
        &ProcessLimits {
            timeout: Duration::from_secs(1800),
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        cancel,
    )
    .map_err(|e| {
        fail(
            &scope,
            &state_path,
            &audit_path,
            state.clone(),
            Error::Run(e),
        )
    })?;
    if let Some(code) = process::error_code(&output.termination) {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Rejected(code),
        ));
    }
    let text = String::from_utf8(output.stdout.bytes).map_err(|_| {
        fail(
            &scope,
            &state_path,
            &audit_path,
            state.clone(),
            Error::InvalidOutput,
        )
    })?;
    let result = UpdateResult {
        recovery_id: req.request_id.to_string(),
        output: text,
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

fn wp_args<I, S>(req: &Request, tail: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = vec![
        "exec".into(),
        "-i".into(),
        "--user".into(),
        format!("{}:{}", req.uid, req.gid),
        req.container.as_str().into(),
        "wp".into(),
        format!("--path={}", req.root.display()),
        "--allow-root".into(),
    ];
    args.extend(tail.into_iter().map(|v| v.as_ref().to_owned()));
    args
}
fn run_to_file(
    request: ProcessRequest,
    file: std::fs::File,
    program: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let output = process::run_with_stdout_file(
        &request,
        file,
        &ProcessLimits {
            timeout: Duration::from_secs(1800),
            max_stdout_bytes: 0,
            max_stderr_bytes: 64 * 1024,
        },
        cancel,
    )
    .map_err(Error::Run)?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(
            process::error_code(&output.termination).unwrap_or(ErrorCode::SubprocessFailed),
        ));
    }
    let _ = program;
    Ok(())
}
fn replay(scope: &ManagedRoot, id: RequestId, operation: &str) -> Result<UpdateResult, Error> {
    let loaded = state::load(
        scope,
        &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
    )
    .map_err(|e| Error::Io(std::io::Error::other(format!("{e:?}"))))?;
    if loaded.operation != operation {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|e| Error::Io(std::io::Error::other(e)))
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
    path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_version_without_shell_fragments() {
        assert!(Request::parse(r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,"version":"6.8.2"}"#, "123e4567-e89b-12d3-a456-426614174000", None).is_ok());
        assert!(Request::parse(r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,"version":"6.8;id"}"#, "123e4567-e89b-12d3-a456-426614174000", None).is_err());
    }
    #[test]
    fn validates_bounded_plugin_slugs() {
        assert!(Request::parse_plugins(r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,"plugins":["woocommerce","seo_pack"]}"#, "123e4567-e89b-12d3-a456-426614174000", None).is_ok());
        assert!(Request::parse_plugins(r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,"plugins":["bad;id"]}"#, "123e4567-e89b-12d3-a456-426614174000", None).is_err());
    }
    #[test]
    fn validates_bounded_theme_slugs() {
        assert!(Request::parse_themes(r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,"themes":["twentytwentyfive"]}"#, "123e4567-e89b-12d3-a456-426614174000", None).is_ok());
        assert!(Request::parse_themes(r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,"themes":["../theme"]}"#, "123e4567-e89b-12d3-a456-426614174000", None).is_err());
    }
}
