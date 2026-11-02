use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    InvalidDomain,
    SameDomain,
    InvalidRequestId,
    InvalidIdempotencyKey,
    /// `sites` is where engine release trees live inside a content root.
    ReservedDomain,
    InvalidRelativeRoot,
    InvalidIdentity,
    InvalidSiteId,
    InvalidExistingPolicy,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidDomain => "domain is invalid",
            Self::SameDomain => "the source and target domains are the same",
            Self::InvalidRequestId => "request-id must be a canonical UUID",
            Self::InvalidIdempotencyKey => "idempotency-key is invalid",
            Self::ReservedDomain => "the domain name is reserved",
            Self::InvalidRelativeRoot => {
                "relative-root must be a short relative path without '..' or empty segments"
            }
            Self::InvalidIdentity => "uid and gid must be site identities (1000 or higher)",
            Self::InvalidSiteId => "site-id must be a canonical UUID",
            Self::InvalidExistingPolicy => "existing must be refuse, adopt-directory or adopt-tree",
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// Another operation holds the resource lock of the source or target.
    ResourceBusy,
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    /// No configured content root has a real directory named after the
    /// source domain (missing, a file, or a symlink).
    SourceMissing,
    /// Something already exists at the target path. Nothing was moved.
    TargetExists,
    /// A path component the request resolves through is a symlink or not a
    /// directory (or was swapped for one while the request ran). Nothing
    /// is followed.
    UnsafePath,
    /// The configured content root is a system directory the engine never
    /// manages sites in.
    UnsafeContentRoot,
    /// `prepareRoot`: the target already exists, holds content and is not
    /// already owned by the requested identity. Nothing was changed.
    ExistingContent,
    /// `removeRoot`: the directory is owned by a system account (uid 1-999).
    UnknownOwner,
    /// `removeRoot`: the directory holds entries and the request did not
    /// confirm deleting them.
    NotEmpty,
    /// `removeRoot`: the tree is deeper or larger than the bound, or crosses
    /// onto another filesystem. Nothing was removed.
    OutOfBounds,
    /// `removeRoot`: the release tree named by `--site-id` has no manifest
    /// for this domain.
    ManifestMismatch,
    /// `writeEnvFile`: the file's current content is not the one the caller
    /// read (`expectedHash`).
    HashMismatch,
    /// `writeEnvFile`/`quarantineFile`: the target exists but is not a
    /// regular file.
    NotRegularFile,
    /// `writeEnvFile`/`quarantineFile`: no such file (or the directory
    /// holding it does not exist).
    FileMissing,
    /// `quarantineFile`: larger than the quarantine bound.
    FileTooLarge,
    /// `quarantineFile`: the file changed while it was being copied; it was
    /// left where it was.
    FileChanged,
    /// `writeEnvFile`/`quarantineFile`: the path is not a file below a site
    /// directory of a configured content root.
    OutsideContentRoot,
    PostCommit(serde_json::Value),
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::ResourceBusy | Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another operation on this site's directory is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::SourceMissing => (
                ErrorCode::NotFound,
                "the site directory to move does not exist".into(),
            ),
            Self::TargetExists => (
                ErrorCode::InvalidInput,
                "a file or directory already exists at the target".into(),
            ),
            Self::UnsafePath => (
                ErrorCode::InvalidInput,
                "a path component of the site directory is a symlink or not a directory".into(),
            ),
            Self::UnsafeContentRoot => (
                ErrorCode::InvalidInput,
                "the configured content root is a system directory".into(),
            ),
            Self::ExistingContent => (
                ErrorCode::Conflict,
                "the directory already holds content owned by another identity".into(),
            ),
            Self::UnknownOwner => (
                ErrorCode::Conflict,
                "the directory is owned by a system account".into(),
            ),
            Self::NotEmpty => (
                ErrorCode::Conflict,
                "the directory is not empty and deleting its contents was not confirmed".into(),
            ),
            Self::OutOfBounds => (
                ErrorCode::InvalidInput,
                "the directory tree is too large or deep, or crosses a filesystem boundary".into(),
            ),
            Self::ManifestMismatch => (
                ErrorCode::InvalidInput,
                "no engine manifest for this domain matches the release tree".into(),
            ),
            Self::HashMismatch => (
                ErrorCode::ConfigHashMismatch,
                "the file changed since it was read; reload it and apply the edit again".into(),
            ),
            Self::NotRegularFile => (
                ErrorCode::InvalidInput,
                "the path is not a regular file".into(),
            ),
            Self::FileMissing => (ErrorCode::NotFound, "no such file".into()),
            Self::OutsideContentRoot => (
                ErrorCode::InvalidInput,
                "the path is not inside a site directory of a content root".into(),
            ),
            Self::FileTooLarge => (
                ErrorCode::InvalidInput,
                "the file is larger than the quarantine limit".into(),
            ),
            Self::FileChanged => (
                ErrorCode::Conflict,
                "the file changed while it was being quarantined; it was left in place".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit(_) => (
                ErrorCode::Internal,
                "internal site directory move error".into(),
            ),
        }
    }
}
