use crate::transaction::{IdempotencyKey, RequestId};
use serde::Deserialize;

#[cfg(unix)]
pub mod activation;
#[cfg(unix)]
pub mod execute;
#[cfg(unix)]
pub mod staging;

pub const OPERATION: &str = "backup.activateConfig";
pub const MAX_CONTENT_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub rclone_config: String,
    pub backup_config: String,
    pub notify_config: String,
    pub agent_script: String,
    pub crontab: String,
}

pub struct OperationRequest {
    pub config: Request,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidConfigJson,
    EmptyAgent,
    InvalidAgent,
    InvalidCrontab,
    ContentTooLarge,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateResult {
    pub activated_at_unix_secs: u64,
    pub staging_cleanup_incomplete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Artifact<'a> {
    pub relative_path: &'static str,
    pub content: &'a str,
    pub mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactSpec {
    pub relative_path: &'static str,
    pub mode: u32,
}

pub const ARTIFACTS: [ArtifactSpec; 4] = [
    ArtifactSpec {
        relative_path: "rclone.conf",
        mode: 0o600,
    },
    ArtifactSpec {
        relative_path: "backup.conf",
        mode: 0o600,
    },
    ArtifactSpec {
        relative_path: "notify.conf",
        mode: 0o600,
    },
    ArtifactSpec {
        relative_path: "agents/backup-agent.sh",
        mode: 0o700,
    },
];

impl Request {
    pub fn parse(json: &str) -> Result<Self, RequestError> {
        let request: Self = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if request.agent_script.trim().is_empty() {
            return Err(RequestError::EmptyAgent);
        }
        for content in [&request.backup_config, &request.notify_config] {
            let value: serde_json::Value =
                serde_json::from_str(content).map_err(|_| RequestError::InvalidConfigJson)?;
            if !value.is_object() {
                return Err(RequestError::InvalidConfigJson);
            }
        }
        if !request.agent_script.starts_with("#!/") || request.agent_script.contains('\0') {
            return Err(RequestError::InvalidAgent);
        }
        if request.crontab.contains('\0') || !request.crontab.is_ascii() {
            return Err(RequestError::InvalidCrontab);
        }
        let total = request.rclone_config.len()
            + request.backup_config.len()
            + request.notify_config.len()
            + request.agent_script.len()
            + request.crontab.len();
        if total > MAX_CONTENT_BYTES {
            return Err(RequestError::ContentTooLarge);
        }
        Ok(request)
    }

    pub fn artifacts(&self) -> [Artifact<'_>; 4] {
        [
            Artifact {
                relative_path: ARTIFACTS[0].relative_path,
                content: &self.rclone_config,
                mode: ARTIFACTS[0].mode,
            },
            Artifact {
                relative_path: ARTIFACTS[1].relative_path,
                content: &self.backup_config,
                mode: ARTIFACTS[1].mode,
            },
            Artifact {
                relative_path: ARTIFACTS[2].relative_path,
                content: &self.notify_config,
                mode: ARTIFACTS[2].mode,
            },
            Artifact {
                relative_path: ARTIFACTS[3].relative_path,
                content: &self.agent_script,
                mode: ARTIFACTS[3].mode,
            },
        ]
    }
}

impl OperationRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        Ok(Self {
            config: Request::parse(json)?,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_bounded_and_requires_an_agent() {
        let valid = serde_json::json!({
            "rcloneConfig":"[remote]",
            "backupConfig":"{}",
            "notifyConfig":"{}",
            "agentScript":"#!/bin/sh\nexit 0",
            "crontab":"0 2 * * * /root/.wcp/agents/backup-agent.sh\n"
        });
        assert!(Request::parse(&valid.to_string()).is_ok());
        let parsed = Request::parse(&valid.to_string()).unwrap();
        assert_eq!(
            parsed.artifacts().map(|a| (a.relative_path, a.mode)),
            [
                ("rclone.conf", 0o600),
                ("backup.conf", 0o600),
                ("notify.conf", 0o600),
                ("agents/backup-agent.sh", 0o700),
            ]
        );
        let empty = serde_json::json!({
            "rcloneConfig":"",
            "backupConfig":"{}",
            "notifyConfig":"{}",
            "agentScript":" ",
            "crontab":""
        });
        assert!(matches!(
            Request::parse(&empty.to_string()),
            Err(RequestError::EmptyAgent)
        ));
        let malformed_config = serde_json::json!({
            "rcloneConfig":"", "backupConfig":"[]", "notifyConfig":"{}",
            "agentScript":"#!/bin/sh\nexit 0", "crontab":""
        });
        assert!(matches!(
            Request::parse(&malformed_config.to_string()),
            Err(RequestError::InvalidConfigJson)
        ));
        let unsafe_agent = serde_json::json!({
            "rcloneConfig":"", "backupConfig":"{}", "notifyConfig":"{}",
            "agentScript":"echo no shebang", "crontab":""
        });
        assert!(matches!(
            Request::parse(&unsafe_agent.to_string()),
            Err(RequestError::InvalidAgent)
        ));
    }
}
