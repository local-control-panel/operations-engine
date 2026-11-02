//! `stack.reloadCaddy`, `stack.stopIdleRuntime`, `stack.ensureRuntime`,
//! `stack.reloadWorkers` and `stack.flushFpc`: the container mutations the
//! control panel used to run over raw SSH against the managed WCP Compose
//! project (`caddy reload`, `stop runtime-<id>`, `up -d runtime-<id>` plus a
//! health poll, the worker reload and the Souin cache purge).
//!
//! Both take the shared `stacks/wcp` lock (milestone 048) as their outermost
//! lock, so neither can land in a container that `stack.deploy`'s `up -d`
//! is recreating, and both record a transaction and an audit entry in their
//! own `stack-service` scope like every other engine mutation.
//! `stack.ensureRuntime` holds the stack lock through its health wait, so a
//! deploy cannot recreate the pool between `up -d` and `healthy`.
//!
//! The commands are fixed argv. The caller picks only which service: the
//! ingress or one runtime pool. `stack.stopIdleRuntime` refuses to stop a
//! pool that still has a site's exec config under `runtime_root/<id>/` and
//! reports `stopped: false` instead, so a stale panel view cannot take a
//! pool down under a live site.

use std::{
    io,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    compose::COMPOSE_PROJECT,
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::{ConfigHash, HashGuard, LIVE_CONFIG_PATH, ROUTE_EXTENSION},
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::{Domain, RuntimeId, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionState, TransactionStatus},
    },
};

mod consts;
mod exec;
mod pool_ops;
mod runtime;
mod site_config;
mod site_helpers;
mod site_ops;
mod types;

pub use self::consts::*;
pub(crate) use self::exec::*;
pub use self::pool_ops::*;
use self::runtime::*;
pub use self::site_config::*;
use self::site_helpers::*;
pub use self::site_ops::*;
pub use self::types::*;

#[cfg(all(test, unix))]
mod tests;
