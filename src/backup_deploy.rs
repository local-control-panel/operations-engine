use serde::Deserialize;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    EmptyAgent,
    ContentTooLarge,
}

impl Request {
    pub fn parse(json: &str) -> Result<Self, RequestError> {
        let request: Self = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if request.agent_script.trim().is_empty() {
            return Err(RequestError::EmptyAgent);
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
    }
}
