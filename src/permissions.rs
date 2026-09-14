//! Typed ownership repair request for content managed by the control plane.

pub mod execute;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    site::TrustedRoot,
    transaction::{IdempotencyKey, RequestId},
};

pub const OPERATION: &str = "permissions.fixOwnership";
/// A second defense behind the staged file's 256 KiB byte bound.
pub const MAX_OWNERS: usize = 1_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnershipTarget {
    pub root: PathBuf,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnershipPlan {
    default: OwnershipTarget,
    targets: Vec<OwnershipTarget>,
}

#[derive(Debug)]
pub struct FixOwnershipRequest {
    pub targets: Vec<OwnershipTarget>,
    pub default: OwnershipTarget,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    TooManyTargets,
    InvalidRoot,
    RootOutsideContentRoots,
    OverlappingRoots,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl FixOwnershipRequest {
    pub fn parse(
        json: &str,
        content_roots: &[TrustedRoot],
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let plan: OwnershipPlan =
            serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.targets.len() > MAX_OWNERS {
            return Err(RequestError::TooManyTargets);
        }
        for (index, target) in plan.targets.iter().enumerate() {
            TrustedRoot::parse(&target.root).map_err(|_| RequestError::InvalidRoot)?;
            if !content_roots
                .iter()
                .any(|allowed| is_strict_descendant(&target.root, allowed.as_path()))
            {
                return Err(RequestError::RootOutsideContentRoots);
            }
            if plan.targets[..index].iter().any(|prior| {
                target.root.starts_with(&prior.root) || prior.root.starts_with(&target.root)
            }) {
                return Err(RequestError::OverlappingRoots);
            }
        }
        TrustedRoot::parse(&plan.default.root).map_err(|_| RequestError::InvalidRoot)?;
        if !content_roots
            .iter()
            .any(|allowed| plan.default.root == allowed.as_path())
        {
            return Err(RequestError::RootOutsideContentRoots);
        }
        if plan
            .targets
            .iter()
            .any(|target| !target.root.starts_with(&plan.default.root))
        {
            return Err(RequestError::RootOutsideContentRoots);
        }
        Ok(Self {
            targets: plan.targets,
            default: plan.default,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

fn is_strict_descendant(candidate: &Path, root: &Path) -> bool {
    candidate.starts_with(root) && candidate != root
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixOwnershipResult {
    pub processed_roots: usize,
    pub repaired_entries: u64,
    pub completed_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn roots() -> Vec<TrustedRoot> {
        vec![TrustedRoot::parse("/var/www").unwrap()]
    }

    #[test]
    fn accepts_disjoint_targets_below_the_configured_root() {
        let request = FixOwnershipRequest::parse(
            r#"{"default":{"root":"/var/www","uid":33,"gid":33},"targets":[{"root":"/var/www/a","uid":10001,"gid":10001},{"root":"/var/www/b","uid":10002,"gid":10002}]}"#,
            &roots(), REQUEST_ID, Some("repair-1"),
        ).unwrap();
        assert_eq!(request.targets.len(), 2);
    }

    #[test]
    fn rejects_the_content_root_itself_and_paths_outside_it() {
        for root in ["/var/www", "/etc"] {
            let json = format!(
                r#"{{"default":{{"root":"/var/www","uid":33,"gid":33}},"targets":[{{"root":"{root}","uid":1,"gid":1}}]}}"#
            );
            assert!(matches!(
                FixOwnershipRequest::parse(&json, &roots(), REQUEST_ID, None),
                Err(RequestError::RootOutsideContentRoots)
            ));
        }
    }

    #[test]
    fn rejects_overlapping_targets() {
        let result = FixOwnershipRequest::parse(
            r#"{"default":{"root":"/var/www","uid":33,"gid":33},"targets":[{"root":"/var/www/a","uid":1,"gid":1},{"root":"/var/www/a/public","uid":2,"gid":2}]}"#,
            &roots(),
            REQUEST_ID,
            None,
        );
        assert!(matches!(result, Err(RequestError::OverlappingRoots)));
    }
}
