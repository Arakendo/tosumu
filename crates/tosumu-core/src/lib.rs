//! `tosumu-core` — core library for the tosumu embedded database.
//!
//! Pre-alpha. See `DESIGN.md` at the repository root for the source of truth.
#![forbid(unsafe_code)]

pub mod btree;
pub mod crypto;
pub mod error;
pub mod format;
pub mod inspect;
pub mod log_store;
pub mod page_store;
pub mod pager;
pub mod wal;

#[cfg(test)]
pub(crate) mod test_helpers;

/// Compile-time project name. Used by the CLI and by log output.
pub const NAME: &str = "tosumu";
