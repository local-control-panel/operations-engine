//! Mutation infrastructure shared by every mutating operation. Phase 4
//! (`site.deploy`) was the first real caller of the Phase 3 primitives;
//! Phase 5 (`site.rollback`) is the second, which is what made `preflight`
//! worth generalizing out of `deploy` into this operation-agnostic module
//! rather than duplicating it.

pub mod preflight;
