#![deny(clippy::all)]

pub mod profile;

#[cfg(target_os = "macos")]
mod backend;
#[cfg(target_os = "macos")]
mod pf;
#[cfg(target_os = "macos")]
mod uid_pool;

#[cfg(target_os = "macos")]
pub use backend::{MacosBackend, MacosBackendError};
#[cfg(target_os = "macos")]
pub use pf::{generate_anchor, load_anchor, unload_anchor};
#[cfg(target_os = "macos")]
pub use uid_pool::{install_pool, UidPool};

pub use profile::{render_launchd_plist, render_sandbox_exec_profile, render_uid_installer};
