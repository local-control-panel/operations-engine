use serde::Deserialize;

pub const OPERATION: &str = "agent.activateBruteforceConfig";
pub const ROOT: &str = "/root/.wcp";
pub const FILE: &str = "bruteforce-config.env";
const MAX: u32 = 1_000_000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Jail {
    enabled: bool,
    max_retries: u32,
    find_time_min: u32,
    ban_time_min: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    wp_login: Jail,
    caddy: Jail,
}

#[derive(Clone, Copy, Debug)]
pub struct RequestError;

impl Request {
    pub fn parse(json: &str) -> Result<Self, RequestError> {
        let value: Self = serde_json::from_str(json).map_err(|_| RequestError)?;
        for jail in [&value.wp_login, &value.caddy] {
            if [jail.max_retries, jail.find_time_min, jail.ban_time_min]
                .into_iter()
                .any(|v| !(1..=MAX).contains(&v))
            {
                return Err(RequestError);
            }
        }
        Ok(value)
    }

    pub fn render(&self) -> String {
        format!(
            "WP_LOGIN_ENABLED={}\nWP_LOGIN_MAX_RETRIES={}\nWP_LOGIN_FINDTIME_MIN={}\nWP_LOGIN_BANTIME_MIN={}\nCADDY_ENABLED={}\nCADDY_MAX_RETRIES={}\nCADDY_FINDTIME_MIN={}\nCADDY_BANTIME_MIN={}\n",
            self.wp_login.enabled,
            self.wp_login.max_retries,
            self.wp_login.find_time_min,
            self.wp_login.ban_time_min,
            self.caddy.enabled,
            self.caddy.max_retries,
            self.caddy.find_time_min,
            self.caddy.ban_time_min
        )
    }
}

#[derive(serde::Serialize)]
pub struct ActivateResult {
    pub activated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_and_renders_the_complete_schema() {
        let request = Request::parse(r#"{"wpLogin":{"enabled":true,"maxRetries":5,"findTimeMin":10,"banTimeMin":60},"caddy":{"enabled":false,"maxRetries":20,"findTimeMin":10,"banTimeMin":60}}"#).unwrap();
        assert!(request.render().contains("WP_LOGIN_MAX_RETRIES=5\n"));
        assert!(request.render().contains("CADDY_ENABLED=false\n"));
        assert!(Request::parse(r#"{"wpLogin":{"enabled":true,"maxRetries":0,"findTimeMin":10,"banTimeMin":60},"caddy":{"enabled":false,"maxRetries":20,"findTimeMin":10,"banTimeMin":60}}"#).is_err());
    }
}
