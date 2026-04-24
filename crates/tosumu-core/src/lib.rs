//! `tosumu-core` — core library for the tosumu embedded database.
//!
//! Pre-alpha. See `DESIGN.md` at the repository root for the source of truth.
#![forbid(unsafe_code)]

pub mod error;
pub mod log_store;

/// Compile-time project name. Used by the CLI and by log output.
pub const NAME: &str = "tosumu";
