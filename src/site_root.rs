//! `site.moveRoot`: renames a site's content directory from
//! `<content root>/<from domain>` to `<content root>/<to domain>` when the
//! control panel renames a site (milestone 053). The panel used to run a
//! raw `sudo mv` for this and `mv` it back on rollback.
//!
//! The caller names two domains, never paths: the engine builds both paths
//! itself as direct children of one configured content root, so the move can
//! never leave that root or cross filesystems. It is a single `rename(2)`
//! through the content root's directory handle (no symlink is followed),
//! refused if the source is missing or not a real directory, or if anything
//! already exists at the target. Both paths take their cross-operation
//! resource lock (the same one the WordPress operations use), so a move
//! cannot run under an install, update or clone of either root, and every
//! request records a transaction and an audit entry in its own scope.
//!
//! A rollback is the same operation with the domains swapped.
//!
//! `site.prepareRoot` and `site.removeRoot` (milestone 061) create and
//! delete a site's content directory the same way: the caller names a
//! domain (and a relative path under it), never an absolute path, and
//! every step is a descriptor-relative operation that refuses to follow a
//! symlink. See `prepare_root` and `remove_root` for their contracts.

use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use cap_std::fs::MetadataExt;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    config::SiteManifest,
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::{Domain, SiteId, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionState, TransactionStatus},
    },
};

pub const MOVE_OPERATION: &str = "site.moveRoot";

const SCOPE: &str = "site-root";

mod errors;
mod move_root;
mod parse;
mod prepare;
mod release;
mod remove;
mod support;
mod transact;

pub use self::errors::*;
pub use self::move_root::*;
pub use self::parse::*;
pub use self::prepare::*;
pub use self::release::*;
pub use self::remove::*;
pub(crate) use self::support::*;
pub(crate) use self::transact::*;

#[cfg(test)]
mod tests;
