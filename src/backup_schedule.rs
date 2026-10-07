//! Scheduled database backups without a secret in any crontab line.
//!
//! Four operations share one design:
//!
//! - `backup.scheduleDatabase` stores the container and root password in a
//!   root-owned `0600` file under the engine credential root and installs a
//!   crontab line that only names the engine, the database and the retention.
//! - `backup.unscheduleDatabase` removes matching lines and, once no
//!   engine-format line needs it, the credential file.
//! - `backup.listScheduledDatabase` is the read-only, redacted view of the
//!   tagged crontab lines, including legacy lines that still embed a password.
//! - `backup.runScheduledDatabase` is what cron runs: it loads the credential
//!   file and goes through `backup.createDatabase`'s own transactional path.
//!
//! Legacy lines (`mariadb-dump -p'...'`, written before this operation
//! existed) keep working untouched; they are listed with their secret
//! redacted, removed by `backup.unscheduleDatabase`, and replaced by the new
//! format when the same database/schedule is scheduled again.

use crate::{
    db_restore::{ContainerName, DatabaseName, DbType, RestoreRequestError},
    transaction::{IdempotencyKey, RequestId},
};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
pub mod execute;

pub const SCHEDULE_OPERATION: &str = "backup.scheduleDatabase";
pub const UNSCHEDULE_OPERATION: &str = "backup.unscheduleDatabase";
pub const LIST_OPERATION: &str = "backup.listScheduledDatabase";
pub const RUN_OPERATION: &str = "backup.runScheduledDatabase";

/// The stable symlink `engine install` maintains.
pub const ENGINE_BINARY: &str = "/usr/local/bin/ops-engine";
/// Comment tag shared with the panel's pre-engine format.
pub const TAG: &str = "[db-backup]";
/// Subdirectory of the credential root holding one file per database.
pub const CREDENTIAL_DIR: &str = "db-backup";
pub const MAX_RETENTION_DAYS: u16 = 3650;
const MAX_TAB_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidField(RestoreRequestError),
    InvalidSchedule,
    InvalidRetention,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

/// A cron schedule that is safe to place in the first field(s) of a line:
/// five `[0-9A-Za-z*/,-]` fields or one fixed `@keyword`. Whitespace is
/// normalized to single spaces so a schedule read back from a crontab compares
/// equal to the one that was submitted. `%` (a newline in cron) and `#` are
/// rejected by the character allowlist; `@reboot` is not a backup schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Schedule(String);

impl Schedule {
    pub fn parse(value: &str) -> Result<Self, RequestError> {
        let fields: Vec<&str> = value.split_whitespace().collect();
        let valid = match fields.as_slice() {
            [keyword] => matches!(
                *keyword,
                "@hourly"
                    | "@daily"
                    | "@midnight"
                    | "@weekly"
                    | "@monthly"
                    | "@yearly"
                    | "@annually"
            ),
            five if five.len() == 5 => five.iter().all(|field| {
                !field.is_empty()
                    && field.len() <= 64
                    && field
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '*' | '/' | ',' | '-'))
            }),
            _ => false,
        };
        if !valid {
            return Err(RequestError::InvalidSchedule);
        }
        Ok(Self(fields.join(" ")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `(dbType, database)` pair every operation here is scoped to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    pub db_type: DbType,
    pub database: DatabaseName,
}

impl Target {
    fn parse(db_type: &str, database: &str) -> Result<Self, RequestError> {
        Ok(Self {
            db_type: DbType::parse(db_type).map_err(RequestError::InvalidField)?,
            database: DatabaseName::parse(database).map_err(RequestError::InvalidField)?,
        })
    }

    pub fn db_type_str(&self) -> &'static str {
        db_type_str(self.db_type)
    }

    /// File name of this target's credential file inside `CREDENTIAL_DIR`.
    pub fn credential_file(&self) -> String {
        format!("{}_{}.json", self.db_type_str(), self.database.as_str())
    }
}

fn db_type_str(value: DbType) -> &'static str {
    match value {
        DbType::Mariadb => "mariadb",
        DbType::Postgres => "postgres",
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SchedulePlan {
    db_type: String,
    database: String,
    container: String,
    root_password: String,
    schedule: String,
    retention_days: u16,
}

pub struct ScheduleRequest {
    pub target: Target,
    pub container: ContainerName,
    pub root_password: String,
    pub schedule: Schedule,
    pub retention_days: u16,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl ScheduleRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: SchedulePlan =
            serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.retention_days > MAX_RETENTION_DAYS {
            return Err(RequestError::InvalidRetention);
        }
        Ok(Self {
            target: Target::parse(&plan.db_type, &plan.database)?,
            container: ContainerName::parse(&plan.container).map_err(RequestError::InvalidField)?,
            root_password: plan.root_password,
            schedule: Schedule::parse(&plan.schedule)?,
            retention_days: plan.retention_days,
            request_id: parse_request_id(request_id)?,
            idempotency_key: parse_key(key)?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnschedulePlan {
    db_type: String,
    database: String,
    schedule: String,
}

pub struct UnscheduleRequest {
    pub target: Target,
    pub schedule: Schedule,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl UnscheduleRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: UnschedulePlan =
            serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        Ok(Self {
            target: Target::parse(&plan.db_type, &plan.database)?,
            schedule: Schedule::parse(&plan.schedule)?,
            request_id: parse_request_id(request_id)?,
            idempotency_key: parse_key(key)?,
        })
    }
}

fn parse_request_id(value: &str) -> Result<RequestId, RequestError> {
    RequestId::parse(value).map_err(|_| RequestError::InvalidRequestId)
}

fn parse_key(value: Option<&str>) -> Result<Option<IdempotencyKey>, RequestError> {
    value
        .map(IdempotencyKey::parse)
        .transpose()
        .map_err(|_| RequestError::InvalidIdempotencyKey)
}

/// What cron runs. The target and retention come from the command line, the
/// secret from the credential file.
pub struct RunRequest {
    pub target: Target,
    pub retention_days: u16,
}

impl RunRequest {
    pub fn parse(db_type: &str, database: &str, retention_days: u16) -> Result<Self, RequestError> {
        if retention_days > MAX_RETENTION_DAYS {
            return Err(RequestError::InvalidRetention);
        }
        Ok(Self {
            target: Target::parse(db_type, database)?,
            retention_days,
        })
    }
}

/// Contents of a credential file.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Credentials {
    pub container: String,
    pub root_password: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JobFormat {
    /// Runs `ops-engine backup run-scheduled`; no secret in the line.
    Engine,
    /// Pre-engine format that embeds the database root password.
    Legacy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduledJob {
    /// The crontab line with any password replaced by `[redacted]`.
    pub line: String,
    pub schedule: String,
    pub db_type: String,
    pub database: String,
    pub retention_days: u32,
    pub enabled: bool,
    pub format: JobFormat,
    /// True when the real crontab line still contains the root password.
    pub secret_in_crontab: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResult {
    pub jobs: Vec<ScheduledJob>,
}

struct ParsedLine {
    job: ScheduledJob,
    target: Target,
}

/// The exact line the engine installs for a job.
pub fn engine_line(target: &Target, schedule: &Schedule, retention_days: u16) -> String {
    format!(
        "{} {ENGINE_BINARY} backup run-scheduled --db-type {db_type} --database {database} --retention-days {retention_days} >/dev/null # {TAG} {db_type}:{database}",
        schedule.as_str(),
        db_type = target.db_type_str(),
        database = target.database.as_str(),
    )
}

/// Replaces the single-quoted shell string that follows each `marker` with
/// `[redacted]`, honouring the `'\''` quote escape the panel used. An
/// unterminated string is redacted to the end of the line.
fn redact_quoted_after(command: &str, marker: &str) -> String {
    let mut out = String::new();
    let mut rest = command;
    while let Some(position) = rest.find(marker) {
        let start = position + marker.len();
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let mut index = 0;
        let mut end = None;
        while let Some(found) = tail[index..].find('\'') {
            let quote = index + found;
            if tail[quote..].starts_with("'\\''") {
                index = quote + 4;
            } else {
                end = Some(quote);
                break;
            }
        }
        out.push_str("[redacted]");
        match end {
            Some(quote) => {
                rest = &tail[quote..];
            }
            None => {
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Removes the database password from a legacy command.
pub fn redact_legacy(command: &str) -> String {
    redact_quoted_after(
        &redact_quoted_after(command, "mariadb-dump -uroot -p'"),
        "PGPASSWORD='",
    )
}

fn contains_secret(command: &str) -> bool {
    command.contains("mariadb-dump -uroot -p'") || command.contains("PGPASSWORD='")
}

fn parse_line(raw: &str) -> Option<ParsedLine> {
    let trimmed = raw.trim();
    let enabled = !trimmed.starts_with('#');
    let content = trimmed.trim_start_matches('#').trim();
    let marker = format!(" # {TAG} ");
    let comment_at = content.rfind(&marker)?;
    let meta = &content[comment_at + marker.len()..];
    let (db_type, database) = meta.trim().split_once(':')?;
    let target = Target::parse(db_type.trim(), database.trim()).ok()?;
    let before = content[..comment_at].trim();
    let mut fields = before.split_whitespace();
    let first = fields.next()?;
    let (schedule, command_fields) = if first.starts_with('@') {
        (first.to_owned(), fields.collect::<Vec<_>>())
    } else {
        let mut schedule = vec![first];
        schedule.extend(fields.by_ref().take(4));
        if schedule.len() != 5 {
            return None;
        }
        (schedule.join(" "), fields.collect::<Vec<_>>())
    };
    if command_fields.is_empty() {
        return None;
    }
    Some(finish(
        raw,
        enabled,
        schedule,
        &command_fields.join(" "),
        target,
    ))
}

fn finish(raw: &str, enabled: bool, schedule: String, command: &str, target: Target) -> ParsedLine {
    let engine_prefix = format!("{ENGINE_BINARY} backup run-scheduled ");
    let format = if command.starts_with(&engine_prefix) {
        JobFormat::Engine
    } else {
        JobFormat::Legacy
    };
    let secret_in_crontab = format == JobFormat::Legacy && contains_secret(command);
    let retention_days = match format {
        JobFormat::Engine => number_after(command, "--retention-days "),
        JobFormat::Legacy => number_after(command, "-mtime +"),
    };
    let line = if secret_in_crontab {
        redact_legacy(raw)
    } else {
        raw.to_owned()
    };
    ParsedLine {
        job: ScheduledJob {
            line,
            schedule,
            db_type: target.db_type_str().to_owned(),
            database: target.database.as_str().to_owned(),
            retention_days,
            enabled,
            format,
            secret_in_crontab,
        },
        target,
    }
}

fn number_after(command: &str, marker: &str) -> u32 {
    command
        .find(marker)
        .map(|at| {
            command[at + marker.len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
        })
        .and_then(|digits| digits.parse().ok())
        .unwrap_or(0)
}

/// Every tagged backup job in `tab`, in file order. Lines that are not
/// recognizably one of this feature's jobs are not listed and never edited.
pub fn list_jobs(tab: &str) -> Vec<ScheduledJob> {
    tab.lines()
        .filter_map(parse_line)
        .map(|parsed| parsed.job)
        .collect()
}

fn matches_job(raw: &str, target: &Target, schedule: &Schedule) -> bool {
    parse_line(raw)
        .is_some_and(|parsed| &parsed.target == target && parsed.job.schedule == schedule.as_str())
}

fn render(lines: Vec<String>) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        lines.join("\n") + "\n"
    }
}

pub fn tab_too_large(tab: &str) -> bool {
    tab.len() > MAX_TAB_BYTES
}

/// The tab with every line for the same database and schedule (either
/// format) replaced by one engine-format line, plus how many lines it
/// replaced. All other lines are preserved byte for byte.
pub fn with_job(
    tab: &str,
    target: &Target,
    schedule: &Schedule,
    retention_days: u16,
) -> (String, usize) {
    let mut replaced = 0;
    let mut lines: Vec<String> = tab
        .lines()
        .filter(|line| {
            let hit = matches_job(line, target, schedule);
            replaced += usize::from(hit);
            !hit
        })
        .map(str::to_owned)
        .collect();
    lines.push(engine_line(target, schedule, retention_days));
    (render(lines), replaced)
}

/// The tab without the lines for this database and schedule, plus how many
/// were removed.
pub fn without_job(tab: &str, target: &Target, schedule: &Schedule) -> (String, usize) {
    let mut removed = 0;
    let lines: Vec<String> = tab
        .lines()
        .filter(|line| {
            let hit = matches_job(line, target, schedule);
            removed += usize::from(hit);
            !hit
        })
        .map(str::to_owned)
        .collect();
    (render(lines), removed)
}

/// Whether any enabled or disabled engine-format line still needs `target`'s
/// credential file.
pub fn needs_credentials(tab: &str, target: &Target) -> bool {
    tab.lines()
        .filter_map(parse_line)
        .any(|parsed| parsed.job.format == JobFormat::Engine && &parsed.target == target)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const LEGACY: &str = "0 2 * * * mkdir -p /root/db-backups && docker exec 'db-1' mariadb-dump -uroot -p'p'\\''w # x' --single-transaction --routines --triggers 'wp_prod' > /root/db-backups/wp_prod_$(date +%Y%m%d_%H%M%S).sql && find /root/db-backups -name 'wp_prod_*.sql' -mtime +7 -delete # [db-backup] mariadb:wp_prod";

    fn target(db: &str) -> Target {
        Target::parse("mariadb", db).unwrap()
    }

    fn schedule(value: &str) -> Schedule {
        Schedule::parse(value).unwrap()
    }

    #[test]
    fn schedule_is_an_allowlist_and_normalizes_whitespace() {
        assert_eq!(schedule("0   2 * *  *").as_str(), "0 2 * * *");
        assert_eq!(
            schedule("*/15 1-5 * JAN MON,TUE").as_str(),
            "*/15 1-5 * JAN MON,TUE"
        );
        assert_eq!(schedule("@daily").as_str(), "@daily");
        for bad in [
            "",
            "@reboot",
            "@daily extra",
            "0 2 * *",
            "0 2 * * * *",
            "0 2 * * * ; rm -rf /",
            "0 2 * * %",
            "0 2 * * #",
            "0 2 * * *\n* * * * * evil",
            "0 2 * * $(id)",
        ] {
            assert_eq!(
                Schedule::parse(bad),
                Err(RequestError::InvalidSchedule),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn schedule_request_is_validated_and_rejects_unknown_fields() {
        let ok = r#"{"dbType":"mariadb","database":"wp","container":"db-1","rootPassword":"pw","schedule":"0 2 * * *","retentionDays":7}"#;
        assert!(ScheduleRequest::parse(ok, ID, None).is_ok());
        for bad in [
            r#"{"dbType":"mysql","database":"wp","container":"db-1","rootPassword":"pw","schedule":"0 2 * * *","retentionDays":7}"#,
            r#"{"dbType":"mariadb","database":"w p","container":"db-1","rootPassword":"pw","schedule":"0 2 * * *","retentionDays":7}"#,
            r#"{"dbType":"mariadb","database":"wp","container":"db 1","rootPassword":"pw","schedule":"0 2 * * *","retentionDays":7}"#,
            r#"{"dbType":"mariadb","database":"wp","container":"db-1","rootPassword":"pw","schedule":"nope","retentionDays":7}"#,
            r#"{"dbType":"mariadb","database":"wp","container":"db-1","rootPassword":"pw","schedule":"0 2 * * *","retentionDays":3651}"#,
            r#"{"dbType":"mariadb","database":"wp","container":"db-1","rootPassword":"pw","schedule":"0 2 * * *","retentionDays":7,"extra":1}"#,
        ] {
            assert!(ScheduleRequest::parse(bad, ID, None).is_err(), "{bad}");
        }
    }

    #[test]
    fn engine_line_carries_no_secret_and_round_trips() {
        let line = engine_line(&target("wp_prod"), &schedule("0 2 * * *"), 7);
        assert_eq!(
            line,
            "0 2 * * * /usr/local/bin/ops-engine backup run-scheduled --db-type mariadb --database wp_prod --retention-days 7 >/dev/null # [db-backup] mariadb:wp_prod"
        );
        let jobs = list_jobs(&line);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].format, JobFormat::Engine);
        assert_eq!(jobs[0].retention_days, 7);
        assert_eq!(jobs[0].schedule, "0 2 * * *");
        assert_eq!(jobs[0].line, line);
        assert!(!jobs[0].secret_in_crontab);
        let keyword = engine_line(&target("wp_prod"), &schedule("@daily"), 0);
        assert_eq!(list_jobs(&keyword)[0].schedule, "@daily");
    }

    #[test]
    fn legacy_lines_are_listed_with_the_password_redacted() {
        let jobs = list_jobs(LEGACY);
        assert_eq!(jobs.len(), 1);
        let job = &jobs[0];
        assert_eq!(job.format, JobFormat::Legacy);
        assert!(job.secret_in_crontab);
        assert_eq!(job.retention_days, 7);
        assert_eq!(job.database, "wp_prod");
        assert!(job.line.contains("-p'[redacted]'"));
        assert!(!job.line.contains("w # x"));
        assert!(!job.line.contains("p'\\''w"));
        assert!(job.line.ends_with("# [db-backup] mariadb:wp_prod"));
    }

    #[test]
    fn postgres_legacy_password_is_redacted() {
        let line = "30 3 * * * mkdir -p /root/db-backups && docker exec -e PGPASSWORD='s3cr3t' 'pg' pg_dump -U postgres --clean --if-exists --no-owner --no-privileges 'app' > /root/db-backups/app_$(date +%Y%m%d_%H%M%S).sql # [db-backup] postgres:app";
        let jobs = list_jobs(line);
        assert_eq!(jobs[0].db_type, "postgres");
        assert!(jobs[0].line.contains("PGPASSWORD='[redacted]'"));
        assert!(!jobs[0].line.contains("s3cr3t"));
        assert_eq!(jobs[0].retention_days, 0);
    }

    #[test]
    fn unterminated_secret_is_redacted_to_the_end() {
        let redacted = redact_legacy("x mariadb-dump -uroot -p'broken # [db-backup] mariadb:a");
        assert!(!redacted.contains("broken"));
    }

    #[test]
    fn disabled_lines_and_unrelated_lines() {
        let tab = "# a plain comment\n#0 3 * * * echo disabled # [db-backup] mariadb:db\n*/5 * * * * /usr/bin/true\n0 4 * * * /root/.wcp/agents/backup-agent.sh # [wcp-backup]\n";
        let jobs = list_jobs(tab);
        assert_eq!(jobs.len(), 1);
        assert!(!jobs[0].enabled);
        assert_eq!(jobs[0].schedule, "0 3 * * *");
    }

    #[test]
    fn with_job_replaces_same_database_and_schedule_in_either_format_only() {
        let tab = format!(
            "MAILTO=root\n*/5 * * * * /usr/bin/true\n{LEGACY}\n0 3 * * * /x # [db-backup] mariadb:other\n"
        );
        let (updated, replaced) = with_job(&tab, &target("wp_prod"), &schedule("0 2 * * *"), 14);
        assert_eq!(replaced, 1);
        assert!(!updated.contains("mariadb-dump"));
        assert!(updated.starts_with("MAILTO=root\n*/5 * * * * /usr/bin/true\n"));
        assert!(updated.contains("0 3 * * * /x # [db-backup] mariadb:other\n"));
        assert!(
            updated.ends_with("--retention-days 14 >/dev/null # [db-backup] mariadb:wp_prod\n")
        );
        // A different schedule for the same database is a second job.
        let (second, replaced) = with_job(&tab, &target("wp_prod"), &schedule("0 5 * * *"), 7);
        assert_eq!(replaced, 0);
        assert!(second.contains("mariadb-dump"));
        assert_eq!(list_jobs(&second).len(), 3);
    }

    #[test]
    fn without_job_removes_only_matching_lines_and_tracks_credentials() {
        let engine = engine_line(&target("a"), &schedule("0 2 * * *"), 1);
        let tab = format!("keep me\n{engine}\n{LEGACY}\n");
        let (rest, removed) = without_job(&tab, &target("a"), &schedule("0 2 * * *"));
        assert_eq!(removed, 1);
        assert_eq!(rest, format!("keep me\n{LEGACY}\n"));
        assert!(!needs_credentials(&rest, &target("a")));
        assert!(needs_credentials(&tab, &target("a")));
        let (empty, removed) =
            without_job(&format!("{engine}\n"), &target("a"), &schedule("0 2 * * *"));
        assert_eq!((empty.as_str(), removed), ("", 1));
    }
}
