//! Production Docker/Compose driver for `db.migrateMariadbLine`.
//!
//! Every SQL statement is a fixed text; the only caller-influenced values are
//! the two catalog service names and database/table names that are read from
//! the server itself and refused unless they are plain identifiers. The root
//! password only ever travels in the child's environment (`docker exec -e
//! MYSQL_PWD`), never in an argument.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{
    mariadb_migrate::{
        MigrateRequest,
        execute::{Baseline, Driver, ExportedDump, ImportedTarget, SourceInfo},
        major_of,
    },
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::{SiteRelativePath, TrustedRoot},
};

const START_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const SYSTEM_SCHEMAS: &str = "'information_schema','mysql','performance_schema','sys'";
/// Accounts the images create; never carried over, the target has its own.
const BUILT_IN_ACCOUNTS: [&str; 4] = ["root", "mariadb.sys", "healthcheck", "mysql"];
const COUNT_BATCH: usize = 100;

#[derive(Debug)]
pub enum Error {
    Process(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
    MissingContainer,
    NotRunning,
    WrongVersion,
    UnsupportedName,
    AliasUnsupported,
    TargetNotEmpty,
    ValidationMismatch,
    InvalidOutput,
    Io(std::io::Error),
    Cancelled,
}

/// What the target has to hold for the migration to count as complete.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Snapshot {
    /// `schema.table` -> exact row count.
    pub tables: BTreeMap<String, u64>,
    /// `user@host`, built-in accounts excluded.
    pub accounts: BTreeSet<String>,
    /// `schema.TYPE.name`.
    pub routines: BTreeSet<String>,
}

impl Snapshot {
    /// The target reproduces the source: the same tables with the same row
    /// counts, the same routines, and at least the source's accounts (the
    /// target's own initial application account may exist as well).
    pub fn is_reproduced_by(&self, target: &Snapshot) -> bool {
        self.tables == target.tables
            && self.routines == target.routines
            && self.accounts.is_subset(&target.accounts)
    }

    pub fn databases(&self) -> u64 {
        self.tables
            .keys()
            .filter_map(|key| key.split_once('.').map(|(schema, _)| schema))
            .collect::<BTreeSet<_>>()
            .len() as u64
    }
}

pub struct DockerDriver<'a> {
    docker_program: &'a str,
    stack_dir: &'a Path,
    state_root: &'a TrustedRoot,
    snapshot: Option<Snapshot>,
}

impl<'a> DockerDriver<'a> {
    pub fn new(stack_dir: &'a Path, state_root: &'a TrustedRoot) -> Self {
        Self {
            docker_program: "docker",
            stack_dir,
            state_root,
            snapshot: None,
        }
    }

    fn limits(timeout: Duration) -> ProcessLimits {
        ProcessLimits {
            timeout,
            max_stdout_bytes: 8 * 1024 * 1024,
            max_stderr_bytes: 256 * 1024,
        }
    }

    fn checked(&self, output: process::ProcessOutput) -> Result<process::ProcessOutput, Error> {
        if matches!(
            output.termination,
            ProcessTermination::Exited { success: true, .. }
        ) {
            Ok(output)
        } else {
            Err(Error::Rejected(SubprocessDiagnostics::from_output(
                self.docker_program,
                &output,
            )))
        }
    }

    fn run(
        &self,
        request: ProcessRequest,
        cancellation: &CancellationToken,
    ) -> Result<String, Error> {
        let output = process::run(
            &request.current_dir(self.stack_dir),
            &Self::limits(START_TIMEOUT),
            cancellation,
        )
        .map_err(Error::Process)?;
        let output = self.checked(output)?;
        String::from_utf8(output.stdout.bytes).map_err(|_| Error::InvalidOutput)
    }

    fn compose(
        &self,
        request: &MigrateRequest,
        args: &[&str],
        cancellation: &CancellationToken,
    ) -> Result<String, Error> {
        let source_profile = format!("db-{}", major_of(request.source_service));
        let target_profile = format!("db-{}", major_of(request.target_service));
        let mut argv = vec![
            "compose",
            "-p",
            "wcp",
            "--env-file",
            ".env",
            "-f",
            "stack/docker-compose.yml",
            "--profile",
            source_profile.as_str(),
            "--profile",
            target_profile.as_str(),
        ];
        argv.extend_from_slice(args);
        self.run(
            ProcessRequest::new(self.docker_program).args(argv),
            cancellation,
        )
    }

    fn docker<I, S>(&self, args: I, cancellation: &CancellationToken) -> Result<String, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.run(
            ProcessRequest::new(self.docker_program).args(args),
            cancellation,
        )
    }

    /// The container of a service, running or not.
    fn container(&self, request: &MigrateRequest, service: &str) -> Result<String, Error> {
        let output = self.compose(
            request,
            &["ps", "-a", "-q", service],
            &CancellationToken::default(),
        )?;
        let id = output.lines().next().unwrap_or("").trim().to_owned();
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::MissingContainer);
        }
        Ok(id)
    }

    /// `(running, data volume)` of a container.
    fn inspect(&self, id: &str) -> Result<(bool, String), Error> {
        let output = self.docker(
            [
                "inspect",
                "--format",
                r#"{{.State.Running}}|{{range .Mounts}}{{if eq .Destination "/var/lib/mysql"}}{{.Name}}{{end}}{{end}}"#,
                id,
            ],
            &CancellationToken::default(),
        )?;
        let (running, volume) = output.trim().split_once('|').ok_or(Error::InvalidOutput)?;
        if volume.is_empty() {
            return Err(Error::InvalidOutput);
        }
        Ok((running == "true", volume.to_owned()))
    }

    fn sql_request(&self, id: &str, password: &str, statement: &str) -> ProcessRequest {
        ProcessRequest::new(self.docker_program)
            .env("MYSQL_PWD", password)
            .args([
                "exec",
                "-i",
                "-e",
                "MYSQL_PWD",
                id,
                "mariadb",
                "-uroot",
                "-N",
                "-B",
                "-e",
                statement,
            ])
    }

    fn sql(&self, id: &str, password: &str, statement: &str) -> Result<String, Error> {
        self.run(
            self.sql_request(id, password, statement),
            &CancellationToken::default(),
        )
    }

    fn wait_ready(
        &self,
        id: &str,
        password: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), Error> {
        let started = Instant::now();
        loop {
            if cancellation.is_cancelled() {
                return Err(Error::Cancelled);
            }
            if self.sql(id, password, "SELECT 1").is_ok() {
                return Ok(());
            }
            if started.elapsed() >= START_TIMEOUT {
                return Err(Error::NotRunning);
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    fn user_databases(&self, id: &str, password: &str) -> Result<Vec<String>, Error> {
        let output = self.sql(
            id,
            password,
            &format!(
                "SELECT schema_name FROM information_schema.schemata \
                 WHERE schema_name NOT IN ({SYSTEM_SCHEMAS}) ORDER BY 1"
            ),
        )?;
        output
            .lines()
            .map(|name| plain_identifier(name).map(str::to_owned))
            .collect()
    }

    fn take_snapshot(&self, id: &str, password: &str) -> Result<Snapshot, Error> {
        let listed = self.sql(
            id,
            password,
            &format!(
                "SELECT table_schema, table_name FROM information_schema.tables \
                 WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ({SYSTEM_SCHEMAS}) \
                 ORDER BY 1, 2"
            ),
        )?;
        let mut names = Vec::new();
        for line in listed.lines() {
            let (schema, table) = line.split_once('\t').ok_or(Error::InvalidOutput)?;
            names.push((
                plain_identifier(schema)?.to_owned(),
                plain_identifier(table)?.to_owned(),
            ));
        }
        let mut tables = BTreeMap::new();
        for batch in names.chunks(COUNT_BATCH) {
            let statement = batch
                .iter()
                .map(|(schema, table)| {
                    format!("SELECT '{schema}.{table}', COUNT(*) FROM `{schema}`.`{table}`")
                })
                .collect::<Vec<_>>()
                .join(" UNION ALL ");
            for line in self.sql(id, password, &statement)?.lines() {
                let (key, count) = line.split_once('\t').ok_or(Error::InvalidOutput)?;
                tables.insert(
                    key.to_owned(),
                    count.trim().parse().map_err(|_| Error::InvalidOutput)?,
                );
            }
        }
        let built_in = BUILT_IN_ACCOUNTS
            .iter()
            .map(|name| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(",");
        let accounts = self
            .sql(
                id,
                password,
                &format!(
                    "SELECT CONCAT(user, '@', host) FROM mysql.user \
                     WHERE user <> '' AND user NOT IN ({built_in}) ORDER BY 1"
                ),
            )?
            .lines()
            .map(str::to_owned)
            .collect();
        let routines = self
            .sql(
                id,
                password,
                &format!(
                    "SELECT CONCAT(routine_schema, '.', routine_type, '.', routine_name) \
                     FROM information_schema.routines \
                     WHERE routine_schema NOT IN ({SYSTEM_SCHEMAS}) ORDER BY 1"
                ),
            )?
            .lines()
            .map(str::to_owned)
            .collect();
        Ok(Snapshot {
            tables,
            accounts,
            routines,
        })
    }

    fn dump_path(&self, request: &MigrateRequest) -> Result<PathBuf, Error> {
        let relative = SiteRelativePath::parse(format!(
            "mariadb-migrate/{}/dumps/{}.sql",
            request.stack_name.as_str(),
            request.request_id
        ))
        .map_err(|_| Error::InvalidOutput)?;
        Ok(self.state_root.join(&relative))
    }

    fn env_path(&self) -> PathBuf {
        self.stack_dir.join(".env")
    }

    /// `CREATE OR REPLACE USER` and `GRANT` statements for every application
    /// account. Roles are not carried (their default-role links are not
    /// reproduced), so a server that has any is refused.
    fn account_statements(&self, id: &str, password: &str) -> Result<String, Error> {
        let built_in = BUILT_IN_ACCOUNTS
            .iter()
            .map(|name| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(",");
        let roles = self.sql(
            id,
            password,
            "SELECT COUNT(*) FROM mysql.user WHERE is_role = 'Y'",
        )?;
        if roles.trim() != "0" {
            return Err(Error::UnsupportedName);
        }
        let listed = self.sql(
            id,
            password,
            &format!(
                "SELECT user, host FROM mysql.user \
                 WHERE user <> '' AND user NOT IN ({built_in}) ORDER BY 1, 2"
            ),
        )?;
        let mut statements = String::new();
        for line in listed.lines() {
            let (user, host) = line.split_once('\t').ok_or(Error::InvalidOutput)?;
            let account = format!("`{}`@`{}`", account_part(user)?, account_part(host)?);
            for statement in [
                format!("SHOW CREATE USER {account}"),
                format!("SHOW GRANTS FOR {account}"),
            ] {
                for row in self.sql(id, password, &statement)?.lines() {
                    statements.push_str(row);
                    statements.push_str(";\n");
                }
            }
        }
        Ok(filter_account_statements(&statements))
    }

    fn alias_variable(service: &str) -> String {
        format!("WCP_MARIADB_{}_ALIAS", major_of(service))
    }
}

/// A database or table name that can be used unquoted in a fixed statement
/// and in argv: letters, digits, `_`, `$`, `-`.
fn plain_identifier(name: &str) -> Result<&str, Error> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b'-'))
    {
        return Err(Error::UnsupportedName);
    }
    Ok(name)
}

/// A user or host part that can sit inside backticks in a fixed statement:
/// like `plain_identifier`, plus `.`, `%`, `:` (host patterns and addresses).
fn account_part(name: &str) -> Result<&str, Error> {
    if name.is_empty()
        || name.len() > 80
        || !name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b'-' | b'.' | b'%' | b':')
        })
    {
        return Err(Error::UnsupportedName);
    }
    Ok(name)
}

/// Keeps what the account statements say about application
/// accounts: their `CREATE USER`, `GRANT`, role and default-role statements.
/// The images' own accounts and the dump tool's helper role are dropped, and
/// `CREATE USER` becomes `CREATE OR REPLACE USER` so the target's initial
/// application account (created from the stack's environment) takes the
/// source's definition instead of clashing with it.
pub fn filter_account_statements(dump: &str) -> String {
    let mut out = String::new();
    for line in dump.lines() {
        let keep = [
            "CREATE USER ",
            "GRANT ",
            "CREATE ROLE ",
            "SET DEFAULT ROLE ",
            "ALTER USER ",
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix));
        if !keep
            || line.contains("mariadb_dump_import_role")
            || BUILT_IN_ACCOUNTS
                .iter()
                .any(|name| line.contains(&format!("`{name}`@")))
        {
            continue;
        }
        match line.strip_prefix("CREATE USER ") {
            Some(rest) => out.push_str(&format!("CREATE OR REPLACE USER {rest}\n")),
            None => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

fn update_env_atomic(path: &Path, updates: &[(&str, &str)]) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::other("compose env is not a regular file"));
    }
    let original = fs::read_to_string(path)?;
    let mut lines = original.lines().map(str::to_owned).collect::<Vec<_>>();
    for (key, value) in updates {
        if value.contains(['\r', '\n', '\0']) {
            return Err(std::io::Error::other("invalid env pointer"));
        }
        let prefix = format!("{key}=");
        if let Some(line) = lines.iter_mut().find(|line| line.starts_with(&prefix)) {
            *line = format!("{key}={value}");
        } else {
            lines.push(format!("{key}={value}"));
        }
    }
    let content = format!("{}\n", lines.join("\n"));
    let temporary = path.with_extension("env.mariadb.tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        use std::io::Write;
        let mut file = options.open(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }
    fs::set_permissions(&temporary, metadata.permissions())?;
    fs::rename(temporary, path)
}

fn private_file(path: &Path, append: bool) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.create(true).write(true);
    if append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

impl Driver for DockerDriver<'_> {
    type Error = Error;

    fn freeze_source(
        &mut self,
        request: &MigrateRequest,
        cancellation: &CancellationToken,
    ) -> Result<SourceInfo, Error> {
        // The old service name is handed to the new server with a network
        // alias set from `.env`; a stack deployed before the template had the
        // variable has to be redeployed first.
        let compose = fs::read_to_string(self.stack_dir.join("stack/docker-compose.yml"))
            .map_err(Error::Io)?;
        if !compose.contains(&Self::alias_variable(request.target_service))
            || !compose.contains(&format!("\n  {}:", request.target_service))
        {
            return Err(Error::AliasUnsupported);
        }
        let id = self.container(request, request.source_service)?;
        let (running, volume) = self.inspect(&id)?;
        if !running {
            return Err(Error::NotRunning);
        }
        let password = request.root_password.as_str();
        let version = self
            .sql(&id, password, "SELECT VERSION()")?
            .trim()
            .to_owned();
        if !version.starts_with(&format!("{}.", major_of(request.source_service))) {
            return Err(Error::WrongVersion);
        }
        if cancellation.is_cancelled() {
            return Err(Error::Cancelled);
        }
        self.sql(&id, password, "SET GLOBAL read_only = 1")?;
        Ok(SourceInfo { version, volume })
    }

    fn export_dump(
        &mut self,
        request: &MigrateRequest,
        cancellation: &CancellationToken,
    ) -> Result<ExportedDump, Error> {
        let id = self.container(request, request.source_service)?;
        let password = request.root_password.as_str();
        let databases = self.user_databases(&id, password)?;
        let path = self.dump_path(request)?;
        let parent = path.parent().ok_or(Error::InvalidOutput)?;
        fs::create_dir_all(parent).map_err(Error::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(Error::Io)?;
        }
        let dump_client = |extra: &[&str]| {
            let mut args = vec![
                "exec".to_owned(),
                "-e".to_owned(),
                "MYSQL_PWD".to_owned(),
                id.clone(),
                "mariadb-dump".to_owned(),
                "-uroot".to_owned(),
            ];
            args.extend(extra.iter().map(|value| (*value).to_owned()));
            ProcessRequest::new(self.docker_program)
                .env("MYSQL_PWD", password)
                .args(args)
        };
        let limits = Self::limits(TRANSFER_TIMEOUT);
        // Databases first (when there are any), then the accounts.
        let main = private_file(&path, false).map_err(Error::Io)?;
        if !databases.is_empty() {
            let mut extra = vec!["--databases"];
            extra.extend(databases.iter().map(String::as_str));
            extra.extend([
                "--single-transaction",
                "--routines",
                "--events",
                "--triggers",
                "--hex-blob",
            ]);
            let output =
                process::run_with_stdout_file(&dump_client(&extra), main, &limits, cancellation)
                    .map_err(Error::Process)?;
            self.checked(output)?;
        }
        // `mariadb-dump --system=users` joins `mysql.user` columns of two
        // collations and fails on the 11.4 image, so the accounts are read
        // with `SHOW CREATE USER` / `SHOW GRANTS` instead.
        let accounts = self.account_statements(&id, password)?;
        {
            use std::io::Write;
            let mut main = private_file(&path, true).map_err(Error::Io)?;
            main.write_all(accounts.as_bytes()).map_err(Error::Io)?;
            main.sync_all().map_err(Error::Io)?;
        }
        let metadata = fs::symlink_metadata(&path).map_err(Error::Io)?;
        if !metadata.file_type().is_file() {
            return Err(Error::InvalidOutput);
        }
        Ok(ExportedDump {
            backup_id: request.request_id.to_string(),
            byte_len: metadata.len(),
        })
    }

    fn capture_baseline(
        &mut self,
        request: &MigrateRequest,
        _cancellation: &CancellationToken,
    ) -> Result<Baseline, Error> {
        let id = self.container(request, request.source_service)?;
        let snapshot = self.take_snapshot(&id, &request.root_password)?;
        let baseline = Baseline {
            validation_token: serde_json::to_string(&snapshot).map_err(|_| Error::InvalidOutput)?,
            databases: snapshot.databases(),
            tables: snapshot.tables.len() as u64,
        };
        self.snapshot = Some(snapshot);
        Ok(baseline)
    }

    fn import_target(
        &mut self,
        request: &MigrateRequest,
        dump: &ExportedDump,
        cancellation: &CancellationToken,
    ) -> Result<ImportedTarget, Error> {
        let password = request.root_password.as_str();
        self.compose(
            request,
            &["up", "-d", "--no-deps", request.target_service],
            cancellation,
        )?;
        let id = self.container(request, request.target_service)?;
        self.wait_ready(&id, password, cancellation)?;
        let version = self
            .sql(&id, password, "SELECT VERSION()")?
            .trim()
            .to_owned();
        if !version.starts_with(&format!("{}.", major_of(request.target_service))) {
            return Err(Error::WrongVersion);
        }
        // Never load into a server that already holds tables.
        if !self.take_snapshot(&id, password)?.tables.is_empty() {
            return Err(Error::TargetNotEmpty);
        }
        let (_, volume) = self.inspect(&id)?;
        let path = self.dump_path(request)?;
        if dump.backup_id != request.request_id.to_string() {
            return Err(Error::InvalidOutput);
        }
        let client = ProcessRequest::new(self.docker_program)
            .env("MYSQL_PWD", password)
            .args([
                "exec",
                "-i",
                "-e",
                "MYSQL_PWD",
                id.as_str(),
                "mariadb",
                "-uroot",
            ])
            .current_dir(self.stack_dir);
        let output = process::run_with_stdin_file(
            &client,
            &path,
            &Self::limits(TRANSFER_TIMEOUT),
            cancellation,
        )
        .map_err(Error::Process)?;
        self.checked(output)?;
        Ok(ImportedTarget { volume, version })
    }

    fn validate_target(
        &mut self,
        request: &MigrateRequest,
        baseline: &Baseline,
        _target: &ImportedTarget,
        _cancellation: &CancellationToken,
    ) -> Result<(), Error> {
        let expected: Snapshot =
            serde_json::from_str(&baseline.validation_token).map_err(|_| Error::InvalidOutput)?;
        let id = self.container(request, request.target_service)?;
        let actual = self.take_snapshot(&id, &request.root_password)?;
        if expected.is_reproduced_by(&actual) {
            Ok(())
        } else {
            Err(Error::ValidationMismatch)
        }
    }

    fn cutover(
        &mut self,
        request: &MigrateRequest,
        _target: &ImportedTarget,
        cancellation: &CancellationToken,
    ) -> Result<(), Error> {
        // Stop the old server before the new one answers to its name, so the
        // name never resolves to two servers.
        self.compose(request, &["stop", request.source_service], cancellation)?;
        update_env_atomic(
            &self.env_path(),
            &[(
                Self::alias_variable(request.target_service).as_str(),
                request.source_service,
            )],
        )
        .map_err(Error::Io)?;
        self.compose(
            request,
            &[
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                request.target_service,
            ],
            cancellation,
        )?;
        let id = self.container(request, request.target_service)?;
        self.wait_ready(&id, &request.root_password, cancellation)?;
        let aliases = self.docker(
            [
                "inspect",
                "--format",
                "{{range $n, $v := .NetworkSettings.Networks}}{{range $v.Aliases}}{{.}} {{end}}{{end}}",
                id.as_str(),
            ],
            cancellation,
        )?;
        if !aliases
            .split_whitespace()
            .any(|alias| alias == request.source_service)
        {
            return Err(Error::InvalidOutput);
        }
        Ok(())
    }

    fn rollback_source(&mut self, request: &MigrateRequest) -> Result<(), Error> {
        let cancellation = CancellationToken::default();
        let mut first_error = None;
        let mut note = |result: Result<(), Error>| {
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        };
        // The target gives the name back and stops; its volume stays.
        note(
            update_env_atomic(
                &self.env_path(),
                &[(
                    Self::alias_variable(request.target_service).as_str(),
                    request.target_service,
                )],
            )
            .map_err(Error::Io),
        );
        if self.container(request, request.target_service).is_ok() {
            note(
                self.compose(request, &["stop", request.target_service], &cancellation)
                    .map(|_| ()),
            );
        }
        match self.container(request, request.source_service) {
            Ok(id) => match self.inspect(&id) {
                Ok((true, _)) => note(
                    self.sql(&id, &request.root_password, "SET GLOBAL read_only = 0")
                        .map(|_| ()),
                ),
                // Stopped: a start resets `read_only` to its configured value.
                _ => note(
                    self.compose(
                        request,
                        &["up", "-d", "--no-deps", request.source_service],
                        &cancellation,
                    )
                    .map(|_| ()),
                ),
            },
            Err(error) => note(Err(error)),
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS_DUMP: &str = "\
/*M!999999\\- enable the sandbox mode */
CREATE USER `mariadb.sys`@`localhost` ACCOUNT LOCK PASSWORD EXPIRE;
CREATE USER `root`@`%` IDENTIFIED BY PASSWORD '*AA';
CREATE USER `healthcheck`@`localhost` IDENTIFIED BY PASSWORD '*BB';
CREATE USER `ua`@`%` IDENTIFIED BY PASSWORD '*CC';
CREATE ROLE IF NOT EXISTS mariadb_dump_import_role;
GRANT mariadb_dump_import_role TO CURRENT_USER();
GRANT ALL PRIVILEGES ON *.* TO `root`@`%` IDENTIFIED BY PASSWORD '*AA' WITH GRANT OPTION;
GRANT PROXY ON ``@`%` TO `root`@`%` WITH GRANT OPTION;
GRANT USAGE ON *.* TO `ua`@`%` IDENTIFIED BY PASSWORD '*CC';
GRANT ALL PRIVILEGES ON `site_a`.* TO `ua`@`%`;
";

    #[test]
    fn only_application_accounts_are_carried_and_recreated_in_place() {
        let filtered = filter_account_statements(USERS_DUMP);
        assert_eq!(
            filtered,
            "CREATE OR REPLACE USER `ua`@`%` IDENTIFIED BY PASSWORD '*CC';\n\
             GRANT USAGE ON *.* TO `ua`@`%` IDENTIFIED BY PASSWORD '*CC';\n\
             GRANT ALL PRIVILEGES ON `site_a`.* TO `ua`@`%`;\n"
        );
    }

    #[test]
    fn only_plain_identifiers_reach_a_statement_or_argv() {
        for ok in ["wordpress", "site_a", "a-b", "x$1"] {
            assert!(plain_identifier(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a`b", "a b", "a;b", "a'b", "é", "a.b", &"x".repeat(65)] {
            assert!(plain_identifier(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn only_plain_account_parts_reach_a_statement() {
        for ok in ["ua", "wp-1", "%", "10.0.0.%", "::1", "db.example.com"] {
            assert!(account_part(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a`b", "a b", "a'b", "a;b", "a\\b", &"x".repeat(81)] {
            assert!(account_part(bad).is_err(), "{bad:?}");
        }
    }

    fn snapshot(tables: &[(&str, u64)], accounts: &[&str], routines: &[&str]) -> Snapshot {
        Snapshot {
            tables: tables.iter().map(|(k, v)| ((*k).into(), *v)).collect(),
            accounts: accounts.iter().map(|v| (*v).into()).collect(),
            routines: routines.iter().map(|v| (*v).into()).collect(),
        }
    }

    #[test]
    fn the_target_has_to_reproduce_tables_counts_routines_and_accounts() {
        let source = snapshot(&[("a.t", 2), ("b.u", 3)], &["ua@%"], &["a.PROCEDURE.p"]);
        // The target's own initial application account is allowed to exist.
        assert!(source.is_reproduced_by(&snapshot(
            &[("a.t", 2), ("b.u", 3)],
            &["ua@%", "wp@%"],
            &["a.PROCEDURE.p"]
        )));
        for target in [
            snapshot(&[("a.t", 2), ("b.u", 2)], &["ua@%"], &["a.PROCEDURE.p"]),
            snapshot(&[("a.t", 2)], &["ua@%"], &["a.PROCEDURE.p"]),
            snapshot(
                &[("a.t", 2), ("b.u", 3), ("c.x", 0)],
                &["ua@%"],
                &["a.PROCEDURE.p"],
            ),
            snapshot(&[("a.t", 2), ("b.u", 3)], &[], &["a.PROCEDURE.p"]),
            snapshot(&[("a.t", 2), ("b.u", 3)], &["ua@%"], &[]),
        ] {
            assert!(!source.is_reproduced_by(&target), "{target:?}");
        }
        assert_eq!(source.databases(), 2);
    }

    #[test]
    fn the_alias_is_written_without_disturbing_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join(".env");
        fs::write(
            &env,
            "MARIADB_ROOT_PASSWORD='p'\nWCP_MARIADB_13_ALIAS=mariadb-13\nOTHER=1\n",
        )
        .unwrap();
        update_env_atomic(&env, &[("WCP_MARIADB_13_ALIAS", "mariadb-11")]).unwrap();
        assert_eq!(
            fs::read_to_string(&env).unwrap(),
            "MARIADB_ROOT_PASSWORD='p'\nWCP_MARIADB_13_ALIAS=mariadb-11\nOTHER=1\n"
        );
        update_env_atomic(&env, &[("NEW", "x")]).unwrap();
        assert!(
            fs::read_to_string(&env)
                .unwrap()
                .ends_with("OTHER=1\nNEW=x\n")
        );
    }
}
