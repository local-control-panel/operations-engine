use super::*;

pub const PREPARE_OPERATION: &str = "site.prepareRoot";
pub const REMOVE_OPERATION: &str = "site.removeRoot";
pub const RELEASE_OPERATION: &str = "site.releaseRoot";

/// Site identities are allocated from 10000 on a panel host; nothing below
/// 1000 is ever a tenant, so a request naming one is refused outright.
pub(super) const MIN_SITE_ID: u32 = 1000;
pub(super) const MAX_SITE_ID: u32 = u32::MAX - 2;
pub(super) const MAX_RELATIVE_COMPONENTS: usize = 8;
/// A tree larger or deeper than this is not a site this engine created.
pub(super) const MAX_REMOVE_ENTRIES: usize = 2_000_000;
pub(super) const MAX_REMOVE_DEPTH: usize = 64;
/// Engine release trees (`sites/<site id>/...`) live beside the per-domain
/// directories, so a domain may not take this name.
pub(super) const RELEASE_TREES_DIR: &str = "sites";
pub(super) const INTERMEDIATE_MODE: u32 = 0o755;
pub(super) const ROOT_MODE: u32 = 0o700;

/// Directories the engine never manages sites in, even if a content root is
/// misconfigured to one of them (exact match: `/var/www` is fine, `/var` is
/// not).
pub(super) const SYSTEM_DIRS: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/media", "/mnt",
    "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var", "/var/lib",
    "/var/log", "/var/run",
];

pub(super) fn parse_domain(value: &str) -> Result<Domain, RequestError> {
    let domain = Domain::parse(value).map_err(|_| RequestError::InvalidDomain)?;
    if domain.as_str() == RELEASE_TREES_DIR {
        return Err(RequestError::ReservedDomain);
    }
    Ok(domain)
}

pub(super) fn parse_relative_root(
    relative_root: Option<&str>,
) -> Result<Vec<SiteRelativePath>, RequestError> {
    let mut components = Vec::new();
    if let Some(relative) = relative_root.filter(|relative| !relative.is_empty()) {
        let parsed =
            SiteRelativePath::parse(relative).map_err(|_| RequestError::InvalidRelativeRoot)?;
        for component in parsed.as_path().components() {
            components.push(
                SiteRelativePath::parse(component.as_os_str())
                    .map_err(|_| RequestError::InvalidRelativeRoot)?,
            );
        }
        if components.len() > MAX_RELATIVE_COMPONENTS {
            return Err(RequestError::InvalidRelativeRoot);
        }
    }
    Ok(components)
}

pub(super) fn parse_ids(
    request_id: &str,
    key: Option<&str>,
) -> Result<(RequestId, Option<IdempotencyKey>), RequestError> {
    let request_id = RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?;
    let key = key
        .map(IdempotencyKey::parse)
        .transpose()
        .map_err(|_| RequestError::InvalidIdempotencyKey)?;
    Ok((request_id, key))
}
