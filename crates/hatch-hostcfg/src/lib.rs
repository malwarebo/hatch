#![deny(clippy::all)]

pub mod hosts;
pub mod rewrite;

pub use hosts::{HostKind, HostSpec};
pub use rewrite::{
    restore, status, sync, BackupRecord, HostStatus, RewriteError, RewriteOptions, RewriteReport,
};
