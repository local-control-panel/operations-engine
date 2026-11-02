use super::*;

/// What `prepareRoot` does with a final directory that already exists and
/// holds content owned by someone else.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExistingPolicy {
    /// Refuse (the default): nothing is changed.
    Refuse,
    /// Hand over the directory itself only; the files inside keep their
    /// owners.
    AdoptDirectory,
    /// Hand over the directory and everything below it, as one safe
    /// descriptor walk (no symlink is followed or changed, nothing on
    /// another filesystem is touched). Not reverted if it fails part-way.
    AdoptTree,
}

impl ExistingPolicy {
    fn parse(value: Option<&str>) -> Result<Self, RequestError> {
        match value {
            None | Some("refuse") => Ok(Self::Refuse),
            Some("adopt-directory") => Ok(Self::AdoptDirectory),
            Some("adopt-tree") => Ok(Self::AdoptTree),
            Some(_) => Err(RequestError::InvalidExistingPolicy),
        }
    }
}

/// Creates (or adopts) `<content root>/<domain>/<relative root>` for a new
/// site and hands it to the site identity.
pub struct PrepareRequest {
    pub domain: Domain,
    /// The directories below the site directory, one component each; empty
    /// means the site directory itself is the root.
    pub(super) relative_root: Vec<SiteRelativePath>,
    pub uid: u32,
    pub gid: u32,
    pub existing: ExistingPolicy,
    pub(crate) require_absent: bool,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl PrepareRequest {
    pub fn parse(
        domain: &str,
        relative_root: Option<&str>,
        uid: u32,
        gid: u32,
        existing: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let domain = parse_domain(domain)?;
        let existing = ExistingPolicy::parse(existing)?;
        let components = parse_relative_root(relative_root)?;
        for id in [uid, gid] {
            if !(MIN_SITE_ID..=MAX_SITE_ID).contains(&id) {
                return Err(RequestError::InvalidIdentity);
            }
        }
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            domain,
            relative_root: components,
            uid,
            gid,
            existing,
            require_absent: false,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareResult {
    /// The prepared root directory.
    pub path: String,
    /// Whether this request created the root directory (false when it
    /// already existed and was only adopted or already correct).
    pub created: bool,
    pub uid: u32,
    pub gid: u32,
    pub mode: String,
    pub completed_at_unix_secs: u64,
}

/// Creates `<content root>/<domain>[/<relative root>]` and gives the final
/// directory to `uid:gid` with mode 0700.
///
/// Every level is looked at with `lstat` and opened with `O_NOFOLLOW`
/// through the previous level's descriptor, so a symlink (or a path that
/// leaves the content root by any other means) is refused, never followed.
/// Directories the request creates are root-owned 0755 (the site directory
/// and anything between it and the root); only the final directory is
/// handed to the site identity, and only that one directory is touched:
/// nothing is ever changed recursively.
///
/// An existing final directory is adopted when it is empty or already owned
/// by the requested identity (so a replay without an idempotency key is a
/// no-op); a non-empty directory owned by anyone else is refused with
/// nothing changed unless the request opts in with an `ExistingPolicy`. Any failure removes the directories this request
/// created and restores an adopted directory's previous owner and mode.
pub fn prepare_root(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    req: &PrepareRequest,
) -> Result<PrepareResult, Error> {
    let content_root = pick_content_root(content_roots, &[PathBuf::from(req.domain.as_str())])?;
    let site_path = content_root.as_path().join(req.domain.as_str());
    transact(
        engine_state,
        PREPARE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        &[site_path.as_path()],
        || prepare(content_root, &site_path, req),
    )
}

pub(super) fn prepare(
    content_root: &TrustedRoot,
    site_path: &Path,
    req: &PrepareRequest,
) -> Result<PrepareResult, Error> {
    refuse_system_dir(content_root)?;
    if req.require_absent {
        let root = ManagedRoot::open(content_root).map_err(Error::Io)?;
        match root.symlink_metadata(&domain_rel(&req.domain)) {
            Ok(_) => return Err(Error::TargetExists),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    let mut names = vec![domain_rel(&req.domain)];
    names.extend(req.relative_root.iter().cloned());

    // `handles[level]` is the directory `names[level]` lives in.
    let mut handles = vec![ManagedRoot::open(content_root).map_err(Error::Io)?];
    let mut created: Vec<(usize, SiteRelativePath)> = Vec::new();
    let mut previous = None;
    match walk_and_own(&names, req, &mut handles, &mut created, &mut previous) {
        Ok(final_created) => {
            let mut path = site_path.to_path_buf();
            for component in &req.relative_root {
                path.push(component.as_path());
            }
            Ok(PrepareResult {
                path: path.to_string_lossy().into_owned(),
                created: final_created,
                uid: req.uid,
                gid: req.gid,
                mode: format!("{ROOT_MODE:04o}"),
                completed_at_unix_secs: unix_now_secs(),
            })
        }
        Err(error) => {
            // Undo, innermost first. `remove_dir` is non-recursive: a
            // directory that somehow gained content is left in place.
            if let (Some((uid, gid, mode)), Some(final_dir)) = (previous, handles.last()) {
                let _ = final_dir.chown_self(uid, gid);
                let _ = final_dir.set_own_mode(mode);
            }
            for (level, name) in created.iter().rev() {
                let _ = handles[*level].remove_dir(name);
            }
            Err(error)
        }
    }
}

/// Walks (creating as needed) every level of `names`, then hands the final
/// directory to the requested identity. Returns whether the final directory
/// was created by this request.
pub(super) fn walk_and_own(
    names: &[SiteRelativePath],
    req: &PrepareRequest,
    handles: &mut Vec<ManagedRoot>,
    created: &mut Vec<(usize, SiteRelativePath)>,
    previous: &mut Option<(u32, u32, u32)>,
) -> Result<bool, Error> {
    let mut final_created = false;
    for (level, name) in names.iter().enumerate() {
        let parent = &handles[level];
        let made = match parent.symlink_metadata(name) {
            Ok(metadata) if metadata.is_dir() => false,
            Ok(_) => return Err(Error::UnsafePath),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                parent.create_dir(name).map_err(Error::Io)?;
                created.push((level, name.clone()));
                true
            }
            Err(error) => return Err(Error::Io(error)),
        };
        let child = parent.open_child_dir_nofollow(name).map_err(open_error)?;
        if made {
            // Independent of the process umask.
            child.set_own_mode(INTERMEDIATE_MODE).map_err(Error::Io)?;
        }
        final_created = made;
        handles.push(child);
    }

    let final_dir = handles.last().expect("the site directory level exists");
    let metadata = final_dir.own_metadata().map_err(Error::Io)?;
    if !final_created
        && req.existing == ExistingPolicy::Refuse
        && (metadata.uid() != req.uid || metadata.gid() != req.gid)
        && !final_dir.child_entries().map_err(Error::Io)?.is_empty()
    {
        return Err(Error::ExistingContent);
    }
    if !final_created {
        *previous = Some((metadata.uid(), metadata.gid(), metadata.mode() & 0o7777));
    }
    if !final_created && req.existing == ExistingPolicy::AdoptTree {
        let fd = final_dir.try_clone_fd().map_err(Error::Io)?;
        crate::permissions::execute::repair_open_directory(&fd, req.uid, req.gid, &[])
            .map_err(Error::Io)?;
    } else {
        final_dir.chown_self(req.uid, req.gid).map_err(Error::Io)?;
    }
    final_dir.set_own_mode(ROOT_MODE).map_err(Error::Io)?;
    Ok(final_created)
}
