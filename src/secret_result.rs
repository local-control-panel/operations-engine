//! `secretResult`: a general mechanism for operations whose answer contains a
//! value that must reach the caller exactly once and must never be stored -
//! a one-time login link, a freshly generated credential.
//!
//! The rule, enforced by the types rather than by discipline:
//!
//! - An operation produces a [`SecretResult<P, S>`]: `public` (`P`) is the
//!   part that is safe to keep - it goes into the transaction state, is what
//!   an idempotent replay returns, and is all that `operation.status` can ever
//!   see; `secret` (`S`) is the one-time part, wrapped so it has no `Debug`
//!   output and is only readable by the response builder.
//! - `Response::success_with_secret` merges both into the response `result`
//!   and sets `secretResult: true` on the envelope, which tells clients not to
//!   persist, log or replay that response.
//! - Persisting code takes `result.public()`; there is no accessor that hands
//!   the secret to a storage API.
//! - A replay is built with [`replayed`]: the stored public part plus
//!   `alreadyIssued: true`, no secret, `secretResult` unset, and the
//!   `SECRET_RESULT_ALREADY_ISSUED` warning.

use serde::Serialize;
use serde_json::Value;

use crate::{
    error::WarningCode,
    protocol::{Response, ResponseBuildError, Warning},
};

/// A secret value. `Debug` prints a placeholder; serializing is possible only
/// through [`SecretResult`], and there is no `Display`.
pub struct Secret<S>(S);

impl<S> Secret<S> {
    pub fn new(value: S) -> Self {
        Self(value)
    }
}

impl<S> std::fmt::Debug for Secret<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Secret(<redacted>)")
    }
}

pub struct SecretResult<P, S> {
    public: P,
    secret: Secret<S>,
}

impl<P, S> std::fmt::Debug for SecretResult<P, S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretResult(<redacted>)")
    }
}

impl<P: Serialize, S: Serialize> SecretResult<P, S> {
    pub fn new(public: P, secret: S) -> Self {
        Self {
            public,
            secret: Secret(secret),
        }
    }

    /// The part that may be stored and replayed.
    pub fn public(&self) -> &P {
        &self.public
    }

    /// The public part as the JSON value to persist in the transaction state.
    pub fn public_value(&self) -> Result<Value, ResponseBuildError> {
        serde_json::to_value(&self.public).map_err(|_| ResponseBuildError)
    }

    /// Public and secret fields merged into one object. Both must serialize
    /// to objects with disjoint keys, otherwise the response is refused
    /// rather than letting one silently shadow the other.
    pub(crate) fn into_response_value(self) -> Result<Value, ResponseBuildError> {
        let Value::Object(mut merged) =
            serde_json::to_value(&self.public).map_err(|_| ResponseBuildError)?
        else {
            return Err(ResponseBuildError);
        };
        let Value::Object(secret) =
            serde_json::to_value(&self.secret.0).map_err(|_| ResponseBuildError)?
        else {
            return Err(ResponseBuildError);
        };
        for (key, value) in secret {
            if merged.insert(key, value).is_some() {
                return Err(ResponseBuildError);
            }
        }
        Ok(Value::Object(merged))
    }
}

/// The replay of a secret-bearing operation: the stored public result with
/// `alreadyIssued: true`, no secret and no `secretResult` flag.
pub fn replayed(
    operation: &'static str,
    stored_public: Value,
) -> Result<Response, ResponseBuildError> {
    let Value::Object(mut object) = stored_public else {
        return Err(ResponseBuildError);
    };
    object.insert("alreadyIssued".to_owned(), Value::Bool(true));
    let response = Response::success(operation, Value::Object(object))?;
    Ok(response.with_warnings(vec![Warning {
        code: WarningCode::SecretResultAlreadyIssued,
        message: "this request was already completed; the one-time secret is not returned again"
            .to_owned(),
    }]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Public {
        expires_at: u64,
    }
    #[derive(Serialize)]
    struct Hidden {
        url: String,
    }
    #[derive(Serialize)]
    struct Clash {
        #[serde(rename = "expires_at")]
        other: u64,
    }

    #[test]
    fn the_response_carries_both_parts_and_the_flag() {
        let result = SecretResult::new(
            Public { expires_at: 5 },
            Hidden {
                url: "https://x/?t=SECRET".into(),
            },
        );
        let response = Response::success_with_secret("op", result).unwrap();
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["secretResult"], true);
        assert_eq!(json["result"]["url"], "https://x/?t=SECRET");
        assert_eq!(json["result"]["expires_at"], 5);
    }

    #[test]
    fn an_ordinary_response_has_no_secret_flag() {
        let json = serde_json::to_value(Response::success("op", 1).unwrap()).unwrap();
        assert!(json.get("secretResult").is_none());
    }

    #[test]
    fn the_stored_value_and_debug_output_never_hold_the_secret() {
        let result = SecretResult::new(
            Public { expires_at: 5 },
            Hidden {
                url: "https://x/?t=SECRET".into(),
            },
        );
        assert!(
            !result
                .public_value()
                .unwrap()
                .to_string()
                .contains("SECRET")
        );
        assert!(!format!("{result:?}").contains("SECRET"));
        let response = Response::success_with_secret("op", result).unwrap();
        assert!(!format!("{response:?}").contains("SECRET"));
    }

    #[test]
    fn overlapping_keys_are_refused() {
        let result = SecretResult::new(Public { expires_at: 5 }, Clash { other: 1 });
        assert!(Response::success_with_secret("op", result).is_err());
    }

    #[test]
    fn a_replay_has_no_secret_flag_and_says_already_issued() {
        let response = replayed("op", serde_json::json!({"expiresAt": 5})).unwrap();
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("secretResult").is_none());
        assert_eq!(json["result"]["alreadyIssued"], true);
        assert_eq!(json["warnings"][0]["code"], "SECRET_RESULT_ALREADY_ISSUED");
    }
}
