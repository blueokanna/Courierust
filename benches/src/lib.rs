//! Shared benchmark helpers.
//!
//! Compiled once into the bench package's library target so every bench
//! binary reuses the same timing/sampling code instead of owning a copy.

pub mod metrics;
