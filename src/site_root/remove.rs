use super::*;

/// Removes a site's directory (and, when `site_id` is given, its engine
/// release tree).
pub struct RemoveRequest {
    pub domain: Domain,
    /// Directories below the site directory to remove instead of the whole
    /// site directory; the site directory and the levels between are then
    /// removed too, but only while they are left empty.
    pub(super) relative_root: Vec<SiteRelativePath>,
    pub site_id: Option<SiteId>,
    /// The caller confirms that deleting a non-empty directory is intended.
    pub confirm_contents: bool,
    pub(crate) expected_owner: Option<(u32, u32)>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl RemoveRequest {
    pub fn parse(
        domain: &str,
        relative_root: Option<&str>,
        site_id: Option<&str>,
        confirm_contents: bool,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let domain = parse_domain(domain)?;
        let relative_root = parse_relative_root(relative_root)?;
        let site_id = site_id
            .map(SiteId::parse)
            .transpose()
            .map_err(|_| RequestError::InvalidSiteId)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            domain,
            relative_root,
            site_id,
            confirm_contents,
            expected_owner: None,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveResult {
    /// The directories this request removed (empty when nothing existed).
    pub removed: Vec<String>,
    pub entries_removed: u64,
    pub completed_at_unix_secs: u64,
}

/// One directory a removal or release will act on.
pub(super) struct Target {
    /// `parents[level]` is the directory `names[level]` lives in.
    pub(super) parents: Vec<ManagedRoot>,
    pub(super) names: Vec<SiteRelativePath>,
    pub(super) dir: ManagedRoot,
    pub(super) path: PathBuf,
    /// Entries below it that are not directories (files, symlinks, ...):
    /// a tree of empty directories holds no content.
    pub(super) contents: usize,
    /// Remove the ancestors named by `names[..len - 1]` too, while empty.
    pub(super) prune: bool,
}

/// Removes `<content root>/<domain>` and, when the request names a site id,
/// the engine release tree `<content root>/sites/<site id>`.
///
/// Bounded and refusing before anything is deleted: each directory must be
/// a real directory (never a symlink), owned by root or a site identity
/// (uid 1000 or higher), and its whole tree must be within the entry and
/// depth bounds and on one filesystem. A release tree is only removed when
/// the engine manifest for the id names this domain. A tree holding
/// anything but empty directories is refused unless the request confirms
/// deleting its contents. Entries are removed bottom-up through
/// descriptors without following a symlink (a link is unlinked, never its
/// target). Removal is not reversible; a request that fails part-way is
/// safe to repeat, and a directory that is already gone is a success with
/// nothing removed.
pub fn remove_root(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    manifests_dir: &Path,
    manifest_owner_uid: u32,
    req: &RemoveRequest,
) -> Result<RemoveResult, Error> {
    let (content_root, lock_paths) = locate(content_roots, &req.domain, req.site_id.as_ref())?;
    let lock_refs: Vec<&Path> = lock_paths.iter().map(PathBuf::as_path).collect();
    transact(
        engine_state,
        REMOVE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        &lock_refs,
        || remove(content_root, manifests_dir, manifest_owner_uid, req),
    )
}

/// The content root a domain (and optional release tree) lives in and the
/// paths that need a resource lock.
pub(super) fn locate<'a>(
    content_roots: &'a [TrustedRoot],
    domain: &Domain,
    site_id: Option<&SiteId>,
) -> Result<(&'a TrustedRoot, Vec<PathBuf>), Error> {
    let mut names = vec![PathBuf::from(domain.as_str())];
    if let Some(id) = site_id {
        names.push(Path::new(RELEASE_TREES_DIR).join(id.to_string()));
    }
    let content_root = pick_content_root(content_roots, &names)?;
    let lock_paths = names
        .iter()
        .map(|name| content_root.as_path().join(name))
        .collect();
    Ok((content_root, lock_paths))
}

pub(super) fn remove(
    content_root: &TrustedRoot,
    manifests_dir: &Path,
    manifest_owner_uid: u32,
    req: &RemoveRequest,
) -> Result<RemoveResult, Error> {
    let targets = resolve_targets(
        content_root,
        manifests_dir,
        manifest_owner_uid,
        &req.domain,
        &req.relative_root,
        req.site_id.as_ref(),
    )?;
    if let Some((uid, gid)) = req.expected_owner {
        for target in &targets {
            let metadata = target.dir.own_metadata().map_err(Error::Io)?;
            if metadata.uid() != uid || metadata.gid() != gid {
                return Err(Error::UnknownOwner);
            }
        }
    }
    if !req.confirm_contents && targets.iter().any(|target| target.contents > 0) {
        return Err(Error::NotEmpty);
    }

    // Everything above is checked before the first deletion.
    let mut removed = Vec::new();
    let mut entries_removed = 0u64;
    for target in &targets {
        let mut remaining = MAX_REMOVE_ENTRIES;
        empty_dir(&target.dir, 0, &mut remaining)?;
        let last = target.names.len() - 1;
        target.parents[last]
            .remove_dir(&target.names[last])
            .map_err(Error::Io)?;
        if target.prune {
            // Best effort: stops at the first level that is not empty.
            for level in (0..last).rev() {
                if target.parents[level]
                    .remove_dir(&target.names[level])
                    .is_err()
                {
                    break;
                }
            }
        }
        removed.push(target.path.to_string_lossy().into_owned());
        entries_removed += (MAX_REMOVE_ENTRIES - remaining) as u64;
    }
    Ok(RemoveResult {
        removed,
        entries_removed,
        completed_at_unix_secs: unix_now_secs(),
    })
}

/// The directories a request acts on, each already checked: the site
/// directory and (with a site id, only when the engine manifest names this
/// domain) the release tree. Missing directories are skipped.
pub(super) fn resolve_targets(
    content_root: &TrustedRoot,
    manifests_dir: &Path,
    manifest_owner_uid: u32,
    domain: &Domain,
    relative_root: &[SiteRelativePath],
    site_id: Option<&SiteId>,
) -> Result<Vec<Target>, Error> {
    refuse_system_dir(content_root)?;
    let mut targets = Vec::new();

    let mut names = vec![domain_rel(domain)];
    names.extend(relative_root.iter().cloned());
    let mut path = content_root.as_path().join(domain.as_str());
    for component in relative_root {
        path.push(component.as_path());
    }
    let base = ManagedRoot::open(content_root).map_err(Error::Io)?;
    if let Some(target) = open_target(base, names, path, !relative_root.is_empty())? {
        targets.push(target);
    }

    if let Some(id) = site_id {
        let names = vec![rel(RELEASE_TREES_DIR), rel(&id.to_string())];
        let path = content_root
            .as_path()
            .join(RELEASE_TREES_DIR)
            .join(id.to_string());
        let base = ManagedRoot::open(content_root).map_err(Error::Io)?;
        if let Some(target) = open_target(base, names, path, false)? {
            let manifest_path = manifests_dir.join(format!("{id}.json"));
            let manifest = SiteManifest::load_owned_by(&manifest_path, manifest_owner_uid, *id)
                .map_err(|_| Error::ManifestMismatch)?;
            if manifest.domain != domain.as_str() {
                return Err(Error::ManifestMismatch);
            }
            targets.push(target);
        }
    }
    Ok(targets)
}

/// Walks `names` down from `base` without following a symlink and returns
/// the last directory as a target, or `None` when any level does not exist.
/// Applies every refusal that does not need the other target.
pub(super) fn open_target(
    base: ManagedRoot,
    names: Vec<SiteRelativePath>,
    path: PathBuf,
    prune: bool,
) -> Result<Option<Target>, Error> {
    let mut parents = vec![base];
    let mut dir = None;
    for (level, name) in names.iter().enumerate() {
        let parent = &parents[level];
        match parent.symlink_metadata(name) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(Error::UnsafePath),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(Error::Io(error)),
        }
        let child = parent.open_child_dir_nofollow(name).map_err(open_error)?;
        if level + 1 == names.len() {
            dir = Some(child);
        } else {
            parents.push(child);
        }
    }
    let dir = dir.expect("a target has at least one name");
    let metadata = dir.own_metadata().map_err(Error::Io)?;
    if !owner_allowed(metadata.uid()) {
        return Err(Error::UnknownOwner);
    }
    let mut counts = Counts::default();
    scan(&dir, metadata.dev(), 0, &mut counts)?;
    Ok(Some(Target {
        parents,
        names,
        dir,
        path,
        contents: counts.contents,
        prune,
    }))
}

/// Root, the engine's own user (the same thing in production) or a site
/// identity; never another system account.
pub(super) fn owner_allowed(uid: u32) -> bool {
    // SAFETY: `geteuid` has no preconditions.
    uid == 0 || uid >= MIN_SITE_ID || uid == unsafe { libc::geteuid() }
}

pub(super) fn entry_name(name: &OsString) -> Result<SiteRelativePath, Error> {
    SiteRelativePath::parse(name).map_err(|_| Error::UnsafePath)
}

#[derive(Default)]
pub(super) struct Counts {
    pub(super) entries: usize,
    pub(super) contents: usize,
}

/// Counts the entries below `dir`, refusing a tree that is too deep, too
/// large, or crosses onto another filesystem.
pub(super) fn scan(
    dir: &ManagedRoot,
    dev: u64,
    depth: usize,
    counts: &mut Counts,
) -> Result<(), Error> {
    if depth > MAX_REMOVE_DEPTH {
        return Err(Error::OutOfBounds);
    }
    for entry in dir.child_entries().map_err(Error::Io)? {
        counts.entries += 1;
        if counts.entries > MAX_REMOVE_ENTRIES {
            return Err(Error::OutOfBounds);
        }
        if entry.is_dir {
            let child = dir
                .open_child_dir_nofollow(&entry_name(&entry.name)?)
                .map_err(open_error)?;
            if child.own_metadata().map_err(Error::Io)?.dev() != dev {
                return Err(Error::OutOfBounds);
            }
            scan(&child, dev, depth + 1, counts)?;
        } else {
            counts.contents += 1;
        }
    }
    Ok(())
}

/// Removes everything below `dir`, bottom-up, never following a symlink.
/// `remaining` is the entry budget left (the scan already proved it
/// sufficient; this only guards a tree that grew since).
pub(super) fn empty_dir(
    dir: &ManagedRoot,
    depth: usize,
    remaining: &mut usize,
) -> Result<(), Error> {
    if depth > MAX_REMOVE_DEPTH {
        return Err(Error::OutOfBounds);
    }
    for entry in dir.child_entries().map_err(Error::Io)? {
        *remaining = remaining.checked_sub(1).ok_or(Error::OutOfBounds)?;
        let name = entry_name(&entry.name)?;
        let result = if entry.is_dir {
            let child = dir.open_child_dir_nofollow(&name).map_err(open_error)?;
            empty_dir(&child, depth + 1, remaining)?;
            dir.remove_dir(&name)
        } else {
            dir.remove_file(&name)
        };
        match result {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    Ok(())
}
