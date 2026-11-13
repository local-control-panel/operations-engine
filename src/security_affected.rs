//! `security.affected`: which engine-managed runtimes run an image that an
//! accepted `docker.image.replace` rule names. Read-only and local: it reads
//! the stored rules and asks the local Docker daemon about the managed stack.
//! No request leaves the machine and nothing is changed.
//!
//! A runtime is only called `patched` when its image is the rule's
//! replacement, and `affected` when it is one of the rule's listed images.
//! An image the catalog does not name, a platform a rule does not cover, an
//! image without a registry digest or a daemon that cannot answer are
//! `unknown`: never "not affected".

use crate::{
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination},
    security_feed::{Freshness, ImageRule},
};
use serde::Serialize;
use std::time::Duration;

pub const COMPONENT_PHP_RUNTIME: &str = "php-runtime";
const MANAGED_PROJECT_LABEL: &str = "label=com.docker.compose.project=wcp";
const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_RUNTIMES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Runtime {
    pub service: String,
    pub declared_image: String,
    /// `sha256:<64 hex>` image id.
    pub image_id: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageFacts {
    /// `os/architecture`.
    pub platform: String,
    /// `sha256:<hex>` parts of the image's registry digests.
    pub digests: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Unavailable;

pub trait Inventory {
    fn runtimes(&self) -> Result<Vec<Runtime>, Unavailable>;
    fn image(&self, image_id: &str) -> Result<ImageFacts, Unavailable>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    /// The image is one the rule lists as affected.
    Affected,
    /// The image is the rule's replacement.
    Patched,
    /// Not provable either way.
    Unknown,
    /// No rule for this component is published.
    NoRule,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleMatch {
    pub fix_id: String,
    pub advisory_id: String,
    pub verdict: Verdict,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComponentRow {
    pub component: &'static str,
    pub service: String,
    pub container_status: String,
    pub declared_image: String,
    pub platform: Option<String>,
    pub digests: Vec<String>,
    pub verdict: Verdict,
    pub matches: Vec<RuleMatch>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Affected {
    pub freshness: Freshness,
    /// `ok`, or `unavailable` when Docker could not list the stack (then there
    /// are no rows and nothing is claimed).
    pub inventory: &'static str,
    pub rule_count: u32,
    pub skipped_rules: u32,
    pub components: Vec<ComponentRow>,
}

fn judge(rule: &ImageRule, facts: &ImageFacts) -> Verdict {
    if !rule.platforms.contains(&facts.platform) {
        return Verdict::Unknown;
    }
    if facts.digests.iter().any(|d| rule.from_digests.contains(d)) {
        Verdict::Affected
    } else if facts.digests.contains(&rule.to_digest) {
        Verdict::Patched
    } else {
        Verdict::Unknown
    }
}

pub fn evaluate(
    docker: &dyn Inventory,
    rules: &[ImageRule],
    skipped_rules: u32,
    freshness: Freshness,
) -> Affected {
    let rules: Vec<&ImageRule> = rules
        .iter()
        .filter(|r| r.component == COMPONENT_PHP_RUNTIME)
        .collect();
    let mut result = Affected {
        freshness,
        inventory: "ok",
        rule_count: u32::try_from(rules.len()).unwrap_or(u32::MAX),
        skipped_rules,
        components: Vec::new(),
    };
    let Ok(runtimes) = docker.runtimes() else {
        result.inventory = "unavailable";
        return result;
    };
    for runtime in runtimes.into_iter().take(MAX_RUNTIMES) {
        let facts = docker.image(&runtime.image_id).ok();
        let matches: Vec<RuleMatch> = rules
            .iter()
            .map(|rule| RuleMatch {
                fix_id: rule.fix_id.clone(),
                advisory_id: rule.advisory_id.clone(),
                verdict: facts
                    .as_ref()
                    .map_or(Verdict::Unknown, |facts| judge(rule, facts)),
            })
            .collect();
        let verdict = if rules.is_empty() {
            Verdict::NoRule
        } else if matches.iter().any(|m| m.verdict == Verdict::Affected) {
            Verdict::Affected
        } else if matches.iter().any(|m| m.verdict == Verdict::Patched) {
            Verdict::Patched
        } else {
            Verdict::Unknown
        };
        result.components.push(ComponentRow {
            component: COMPONENT_PHP_RUNTIME,
            service: runtime.service,
            container_status: runtime.status,
            declared_image: runtime.declared_image,
            platform: facts.as_ref().map(|f| f.platform.clone()),
            digests: facts.map(|f| f.digests).unwrap_or_default(),
            verdict,
            matches,
        });
    }
    result
}

// ---- Docker ------------------------------------------------------------------------

pub struct Docker<'a> {
    pub program: &'a str,
}

impl Docker<'_> {
    fn run(&self, args: &[&str]) -> Result<Vec<u8>, Unavailable> {
        let output = process::run(
            &ProcessRequest::new(self.program).args(args),
            &ProcessLimits {
                timeout: TIMEOUT,
                max_stdout_bytes: MAX_OUTPUT_BYTES,
                max_stderr_bytes: 16 * 1024,
            },
            &CancellationToken::default(),
        )
        .map_err(|_| Unavailable)?;
        match output.termination {
            ProcessTermination::Exited { success: true, .. } if !output.stdout.truncated => {
                Ok(output.stdout.bytes)
            }
            _ => Err(Unavailable),
        }
    }
}

fn image_id_ok(id: &str) -> bool {
    id.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// `runtime-<digits>`: the compose service of a managed PHP runtime.
fn runtime_service(service: &str) -> bool {
    service.strip_prefix("runtime-").is_some_and(|rest| {
        !rest.is_empty() && rest.len() <= 12 && rest.bytes().all(|b| b.is_ascii_digit())
    })
}

fn parse_runtimes(bytes: &[u8]) -> Option<Vec<Runtime>> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let mut out = Vec::new();
    for item in value.as_array()? {
        let text = |pointer: &str| item.pointer(pointer).and_then(|v| v.as_str());
        let service = text("/Config/Labels/com.docker.compose.service")?;
        if !runtime_service(service) {
            continue;
        }
        let image_id = text("/Image")?;
        if !image_id_ok(image_id) {
            return None;
        }
        out.push(Runtime {
            service: service.to_owned(),
            declared_image: text("/Config/Image")?.chars().take(300).collect(),
            image_id: image_id.to_owned(),
            status: text("/State/Status")?.chars().take(32).collect(),
        });
    }
    out.sort_by(|a, b| a.service.cmp(&b.service));
    Some(out)
}

fn parse_image(bytes: &[u8]) -> Option<ImageFacts> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let image = value.as_array()?.first()?;
    let os = image.get("Os")?.as_str()?;
    let arch = image.get("Architecture")?.as_str()?;
    let digests = image
        .get("RepoDigests")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str()?.split_once("@sha256:"))
                .filter(|(_, hex)| {
                    hex.len() == 64
                        && hex
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
                .map(|(_, hex)| format!("sha256:{hex}"))
                .collect()
        })
        .unwrap_or_default();
    Some(ImageFacts {
        platform: format!("{os}/{arch}"),
        digests,
    })
}

impl Inventory for Docker<'_> {
    fn runtimes(&self) -> Result<Vec<Runtime>, Unavailable> {
        let ids = self.run(&["ps", "-aq", "--filter", MANAGED_PROJECT_LABEL])?;
        let ids = String::from_utf8(ids).map_err(|_| Unavailable)?;
        let ids: Vec<&str> = ids.split_whitespace().collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        if ids
            .iter()
            .any(|id| id.len() > 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(Unavailable);
        }
        let mut args = vec!["inspect", "--type", "container"];
        args.extend(ids);
        parse_runtimes(&self.run(&args)?).ok_or(Unavailable)
    }

    fn image(&self, image_id: &str) -> Result<ImageFacts, Unavailable> {
        if !image_id_ok(image_id) {
            return Err(Unavailable);
        }
        parse_image(&self.run(&["image", "inspect", image_id])?).ok_or(Unavailable)
    }
}

#[cfg(test)]
mod tests;
