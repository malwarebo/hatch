#![deny(clippy::all)]

#[cfg(target_os = "linux")]
mod backend;
#[cfg(target_os = "linux")]
mod capabilities;
#[cfg(target_os = "linux")]
mod cgroups;
#[cfg(target_os = "linux")]
mod landlock_apply;
#[cfg(target_os = "linux")]
mod mount_ns;
#[cfg(target_os = "linux")]
mod netns;
#[cfg(target_os = "linux")]
mod seccomp;

#[cfg(target_os = "linux")]
pub use backend::{LinuxBackend, LinuxBackendError};
#[cfg(target_os = "linux")]
pub use capabilities::detect_capabilities;
#[cfg(target_os = "linux")]
pub use seccomp::SeccompProfile;

#[cfg(not(target_os = "linux"))]
mod stub_for_other_platforms;
#[cfg(not(target_os = "linux"))]
pub use stub_for_other_platforms::*;

#[derive(Debug, Clone, Default)]
pub struct LinuxCapabilities {
    pub user_namespaces: bool,
    pub mount_namespaces: bool,
    pub net_namespaces: bool,
    pub pid_namespaces: bool,
    pub cgroups_v2: bool,
    pub seccomp: bool,
    pub landlock: Option<u32>,
}
