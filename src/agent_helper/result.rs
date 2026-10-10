//! `agent result emit`: the result line the panel shows next to the
//! heartbeat. It goes to the same `logs/NAME.log` as `agent log`, as
//! `{"ts","agent","status","summary","data":{...}}`.

use serde_json::{Map, Value, json};

use super::{HelperError, MAX_LINES_LIMIT};

pub const MAX_SUMMARY_CHARS: usize = 500;
pub const MAX_DATA_BYTES: usize = 4096;
const MAX_KEY_CHARS: usize = 64;
/// A key containing one of these is refused: result data is shown in the
/// panel and kept in a world-readable log, so it must never carry a secret.
const SECRET_WORDS: [&str; 8] = [
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
    "private_key",
];

fn check_key(key: &str) -> Result<(), HelperError> {
    let valid = !key.is_empty()
        && key.chars().count() <= MAX_KEY_CHARS
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if !valid {
        return Err(HelperError::Invalid(
            "a data key is 1 to 64 characters of letters, digits, '_', '-' and '.'".into(),
        ));
    }
    let lower = key.to_ascii_lowercase();
    if SECRET_WORDS.iter().any(|word| lower.contains(word)) {
        return Err(HelperError::Invalid(format!(
            "data key '{key}' looks like a secret; results must never carry secrets"
        )));
    }
    Ok(())
}

/// The `data` object from `--data-json` (merged first) and the `--data
/// KEY=VALUE` pairs (later ones win). Values from pairs are strings.
pub fn build_data(
    pairs: &[String],
    data_json: Option<&str>,
) -> Result<Map<String, Value>, HelperError> {
    let mut data = Map::new();
    if let Some(text) = data_json {
        match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(map)) => data = map,
            _ => {
                return Err(HelperError::Invalid(
                    "--data-json must be a JSON object".into(),
                ));
            }
        }
    }
    for pair in pairs {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(HelperError::Invalid("--data takes KEY=VALUE".into()));
        };
        data.insert(key.to_owned(), Value::String(value.to_owned()));
    }
    for key in data.keys() {
        check_key(key)?;
    }
    let size = serde_json::to_string(&data).map_or(usize::MAX, |text| text.len());
    if size > MAX_DATA_BYTES {
        return Err(HelperError::Invalid(format!(
            "result data is larger than {MAX_DATA_BYTES} bytes"
        )));
    }
    Ok(data)
}

/// The JSON line `agent result emit` appends.
pub fn result_line(
    name: &str,
    status: &str,
    summary: &str,
    data: &Map<String, Value>,
    ts: u64,
) -> Result<String, HelperError> {
    let summary: String = summary.chars().take(MAX_SUMMARY_CHARS).collect();
    if summary.trim().is_empty() {
        return Err(HelperError::Invalid("--summary must not be empty".into()));
    }
    let mut line = json!({
        "ts": ts,
        "agent": name,
        "status": status,
        "summary": summary,
        "data": data,
    })
    .to_string();
    line.push('\n');
    Ok(line)
}

pub fn check_max_lines(max_lines: usize) -> Result<(), HelperError> {
    if max_lines == 0 || max_lines > MAX_LINES_LIMIT {
        return Err(HelperError::Invalid(format!(
            "--max-lines must be between 1 and {MAX_LINES_LIMIT}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn the_result_line_has_the_documented_shape() {
        let data = build_data(&pairs(&["sites=3"]), Some(r#"{"n": 1, "ok": true}"#)).unwrap();
        let line = result_line("demo", "warn", "checked 3 sites", &data, 7).unwrap();
        assert_eq!(line.matches('\n').count(), 1);
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["ts"], 7);
        assert_eq!(value["agent"], "demo");
        assert_eq!(value["status"], "warn");
        assert_eq!(value["summary"], "checked 3 sites");
        assert_eq!(value["data"], json!({"n": 1, "ok": true, "sites": "3"}));
        assert_eq!(value.as_object().unwrap().len(), 5);
    }

    #[test]
    fn pairs_win_over_data_json_and_the_value_keeps_its_equals_signs() {
        let data = build_data(&pairs(&["a=x=y"]), Some(r#"{"a": "old"}"#)).unwrap();
        assert_eq!(data["a"], "x=y");
    }

    #[test]
    fn the_summary_is_cut_and_must_not_be_empty() {
        let long = "é".repeat(900);
        let line = result_line("demo", "ok", &long, &Map::new(), 1).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(
            value["summary"].as_str().unwrap().chars().count(),
            MAX_SUMMARY_CHARS
        );
        assert!(result_line("demo", "ok", "  ", &Map::new(), 1).is_err());
    }

    #[test]
    fn data_must_be_an_object_of_safe_keys_within_the_size_limit() {
        assert!(build_data(&[], Some("[1]")).is_err());
        assert!(build_data(&[], Some("nope")).is_err());
        assert!(build_data(&pairs(&["novalue"]), None).is_err());
        assert!(build_data(&pairs(&["=v"]), None).is_err());
        assert!(build_data(&pairs(&["a b=v"]), None).is_err());
        assert!(build_data(&pairs(&[&format!("{}=v", "k".repeat(65))]), None).is_err());
        let big = pairs(&[&format!("k={}", "x".repeat(MAX_DATA_BYTES))]);
        assert!(build_data(&big, None).is_err());
        assert!(build_data(&pairs(&["k=ok"]), None).is_ok());
    }

    #[test]
    fn keys_that_look_like_secrets_are_refused() {
        for key in [
            "password",
            "DB_PASSWORD",
            "api_key",
            "apiKey",
            "authToken",
            "client-secret",
        ] {
            let error = build_data(&pairs(&[&format!("{key}=v")]), None).unwrap_err();
            assert!(matches!(error, HelperError::Invalid(_)), "{key}");
        }
        assert!(build_data(&[], Some(r#"{"nested": {"password": 1}, "token": 1}"#)).is_err());
        assert!(build_data(&pairs(&["keys_checked=3", "sites=2"]), None).is_ok());
    }

    #[test]
    fn max_lines_is_bounded() {
        assert!(check_max_lines(0).is_err());
        assert!(check_max_lines(MAX_LINES_LIMIT + 1).is_err());
        assert!(check_max_lines(1).is_ok());
    }
}
