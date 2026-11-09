//! The two database steps every recovery-first update shares: a MySQL/MariaDB
//! client call inside the database container, and emptying the site's
//! database before an import. Used by the Drupal and Joomla rollbacks.

use crate::{
    drupal_action::{DbConnection, MAX_OUTPUT},
    process::{self, CancellationToken, ProcessLimits, ProcessRequest},
};

/// Why emptying the database failed. The text is fixed; no tool output.
#[derive(Debug)]
pub enum DbError {
    Run(process::ProcessRunError),
    Failed(&'static str),
}

fn exited_ok(output: &process::ProcessOutput) -> bool {
    crate::drupal_action::exited_ok(output)
}

/// MySQL/MariaDB client call in the database container, with the password
/// only in the environment of that one `docker exec`.
pub(crate) fn db_client(docker_program: &str, connection: &DbConnection) -> ProcessRequest {
    ProcessRequest::new(docker_program)
        .env("MYSQL_PWD", &connection.password)
        .args([
            "exec".to_owned(),
            "-i".into(),
            "-e".into(),
            "MYSQL_PWD".into(),
            connection.host.clone(),
            "mariadb".into(),
            format!("-u{}", connection.user),
            connection.database.clone(),
        ])
}

/// Drops every table and view of the site's database through the database
/// container's own client (the PHP container usually has none, which rules
/// out `drush sql:drop`). Names are read back from `information_schema` and
/// quoted here; a name with a backslash or control character is refused
/// rather than guessed.
pub(crate) fn empty_database(
    docker_program: &str,
    connection: &DbConnection,
    limits: &ProcessLimits,
    cancel: &CancellationToken,
) -> Result<(), DbError> {
    let list_limits = ProcessLimits {
        timeout: limits.timeout,
        max_stdout_bytes: 4 * 1024 * 1024,
        max_stderr_bytes: MAX_OUTPUT,
    };
    let mut request = db_client(docker_program, connection);
    request = request.args([
        "-N".to_owned(),
        "-B".into(),
        "-e".into(),
        "SELECT table_name, table_type FROM information_schema.tables WHERE table_schema = DATABASE()"
            .into(),
    ]);
    let listed = process::run(&request, &list_limits, cancel).map_err(DbError::Run)?;
    if !exited_ok(&listed) {
        return Err(DbError::Failed("the database tables could not be listed"));
    }
    let text = String::from_utf8(listed.stdout.bytes)
        .map_err(|_| DbError::Failed("the table list was unreadable"))?;
    let mut script = String::from("SET FOREIGN_KEY_CHECKS=0;\n");
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (name, kind) = line
            .split_once('\t')
            .ok_or(DbError::Failed("the table list was unreadable"))?;
        if name.chars().any(|c| c == '\\' || c.is_control()) {
            return Err(DbError::Failed("a table name cannot be quoted safely"));
        }
        let object = if kind == "VIEW" { "VIEW" } else { "TABLE" };
        script.push_str(&format!(
            "DROP {object} IF EXISTS `{}`;\n",
            name.replace('`', "``")
        ));
    }
    let dropped = process::run_with_stdin_bytes(
        &db_client(docker_program, connection),
        script.as_bytes(),
        limits,
        cancel,
    )
    .map_err(DbError::Run)?;
    if !exited_ok(&dropped) {
        return Err(DbError::Failed("the database tables could not be dropped"));
    }
    Ok(())
}
