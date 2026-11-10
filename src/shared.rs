//! Target-appropriate shared ownership for the protocol core.
//!
//! `Rc` deliberately preserves single-threaded semantics on targets without
//! pointer atomics. No unsafe Send/Sync implementations or emulated atomics.

#[cfg(not(target_has_atomic = "ptr"))]
pub(crate) use alloc::rc::Rc as Shared;
#[cfg(target_has_atomic = "ptr")]
pub(crate) use alloc::sync::Arc as Shared;
