use super::*;

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

fn ensure_json(database: &str) -> String {
    serde_json::json!({"container":"mariadb-11","rootPassword":"secret","database":database})
        .to_string()
}

fn db(name: &str) -> DatabaseName {
    DatabaseName::parse(name).unwrap()
}

#[test]
fn short_names_are_ro_prefix_plus_database() {
    assert_eq!(username_for(&db("site_db")), "ro_site_db");
    let exact = "a".repeat(MAX_USER_LEN - 3);
    assert_eq!(username_for(&db(&exact)), format!("ro_{exact}"));
}

#[test]
fn long_names_are_shortened_with_a_stable_hash_suffix() {
    let long = "a".repeat(MAX_USER_LEN - 2);
    let name = username_for(&db(&long));
    assert_eq!(name.len(), MAX_USER_LEN);
    assert!(name.starts_with("ro_aaaa"));
    assert_eq!(name, username_for(&db(&long)));
    // Databases sharing a long prefix do not collide.
    let other = format!("{}b", "a".repeat(MAX_USER_LEN - 1));
    assert_ne!(name, username_for(&db(&other)));
    let longest = username_for(&db(&"z".repeat(64)));
    assert_eq!(longest.len(), MAX_USER_LEN);
    assert!(
        longest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    );
}

#[test]
fn invalid_and_protected_databases_are_rejected() {
    for database in ["", "bad-db", "bad`db", "a b", "d'b", &"x".repeat(65)] {
        assert_eq!(
            Request::parse_ensure(&ensure_json(database), ID, None).unwrap_err(),
            RequestError::InvalidDatabase,
            "{database}"
        );
    }
    for database in [
        "mysql",
        "MySQL",
        "information_schema",
        "PERFORMANCE_SCHEMA",
        "sys",
    ] {
        assert_eq!(
            Request::parse_ensure(&ensure_json(database), ID, None).unwrap_err(),
            RequestError::ProtectedDatabase
        );
        assert_eq!(
            Request::parse_revoke(&ensure_json(database), ID, None).unwrap_err(),
            RequestError::ProtectedDatabase
        );
    }
}

#[test]
fn request_fields_are_validated() {
    let request = Request::parse_ensure(&ensure_json("site_db"), ID, Some("key-1")).unwrap();
    assert!(!request.rotate);
    assert_eq!(request.username(), "ro_site_db");
    let rotate = Request::parse_ensure(
        r#"{"container":"mariadb-11","rootPassword":"s","database":"site_db","rotate":true}"#,
        ID,
        None,
    )
    .unwrap();
    assert!(rotate.rotate);
    for json in [
        r#"{"container":"mariadb-11","rootPassword":"s","database":"d","password":"x"}"#,
        r#"{"container":"mariadb-11","rootPassword":"s","database":"d","user":"x"}"#,
        r#"{"container":"mariadb-11","rootPassword":"s"}"#,
        "not json",
    ] {
        assert_eq!(
            Request::parse_ensure(json, ID, None).unwrap_err(),
            RequestError::InvalidJson
        );
    }
    // `rotate` belongs to ensure only.
    assert_eq!(
        Request::parse_revoke(
            r#"{"container":"mariadb-11","rootPassword":"s","database":"d","rotate":true}"#,
            ID,
            None
        )
        .unwrap_err(),
        RequestError::InvalidJson
    );
    assert_eq!(
        Request::parse_ensure(
            r#"{"container":"bad name","rootPassword":"s","database":"d"}"#,
            ID,
            None
        )
        .unwrap_err(),
        RequestError::InvalidContainer
    );
    assert_eq!(
        Request::parse_ensure(
            r#"{"container":"c","rootPassword":"a\nb","database":"d"}"#,
            ID,
            None
        )
        .unwrap_err(),
        RequestError::InvalidSecret
    );
    assert_eq!(
        Request::parse_ensure(&ensure_json("d"), "nope", None).unwrap_err(),
        RequestError::InvalidRequestId
    );
}

#[test]
fn ensure_statements_are_exact() {
    assert_eq!(
        ensure_statements("ro_site_db", &db("site_db"), Some("Pw123")),
        vec![
            "CREATE USER IF NOT EXISTS 'ro_site_db'@'localhost';",
            "ALTER USER 'ro_site_db'@'localhost' IDENTIFIED BY 'Pw123';",
            "GRANT SELECT ON `site\\_db`.* TO 'ro_site_db'@'localhost' WITH MAX_QUERIES_PER_HOUR 600 MAX_UPDATES_PER_HOUR 0 MAX_USER_CONNECTIONS 2;",
            "FLUSH PRIVILEGES;",
        ]
    );
    let without = ensure_statements("ro_site_db", &db("site_db"), None);
    assert_eq!(without.len(), 3);
    assert!(without.iter().all(|s| !s.contains("IDENTIFIED")));
}

#[test]
fn revoke_statement_is_idempotent_sql() {
    assert_eq!(
        revoke_statements("ro_x"),
        vec!["DROP USER IF EXISTS 'ro_x'@'localhost';"]
    );
}
