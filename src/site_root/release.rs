use super::*;

/// Hands a deleted site's leftover content to root.
pub struct ReleaseRequest {
    pub domain: Domain,
    pub site_id: Option<SiteId>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl ReleaseRequest {
    pub fn parse(
        domain: &str,
        site_id: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let RemoveRequest {
            domain,
            site_id,
            request_id,
            idempotency_key,
            ..
        } = RemoveRequest::parse(domain, None, site_id, false, request_id, key)?;
        Ok(Self {
            domain,
            site_id,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseResult {
    /// The directories whose tree is now owned by root:root.
    pub released: Vec<String>,
    pub repaired_entries: u64,
    pub completed_at_unix_secs: u64,
}

/// Gives everything below `<content root>/<domain>` (and the manifest-
/// verified release tree of `site_id`) to root:root, so that numeric uid of
/// a deleted site identity, which the next site may be handed, does not
/// keep access to the leftover tenant files. The same descriptor-relative
/// walk as `permissions.fixOwnership`: a symlink is neither followed nor
/// changed and nothing on another filesystem is touched. A missing
/// directory is skipped.
pub fn release_root(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    manifests_dir: &Path,
    manifest_owner_uid: u32,
    req: &ReleaseRequest,
) -> Result<ReleaseResult, Error> {
    let (content_root, lock_paths) = locate(content_roots, &req.domain, req.site_id.as_ref())?;
    let lock_refs: Vec<&Path> = lock_paths.iter().map(PathBuf::as_path).collect();
    transact(
        engine_state,
        RELEASE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        &lock_refs,
        || {
            let targets = resolve_targets(
                content_root,
                manifests_dir,
                manifest_owner_uid,
                &req.domain,
                &[],
                req.site_id.as_ref(),
            )?;
            let mut released = Vec::new();
            let mut repaired_entries = 0;
            for target in &targets {
                repaired_entries +=
                    crate::permissions::execute::repair_tree(&target.path, 0, 0, &[])
                        .map_err(Error::Io)?;
                released.push(target.path.to_string_lossy().into_owned());
            }
            Ok(ReleaseResult {
                released,
                repaired_entries,
                completed_at_unix_secs: unix_now_secs(),
            })
        },
    )
}
