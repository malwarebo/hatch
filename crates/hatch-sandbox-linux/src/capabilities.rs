use std::fs;
use std::path::Path;

use crate::LinuxCapabilities;

pub fn detect_capabilities() -> LinuxCapabilities {
    LinuxCapabilities {
        user_namespaces: probe_user_namespaces(),
        mount_namespaces: Path::new("/proc/self/ns/mnt").exists(),
        net_namespaces: Path::new("/proc/self/ns/net").exists(),
        pid_namespaces: Path::new("/proc/self/ns/pid").exists(),
        cgroups_v2: probe_cgroups_v2(),
        seccomp: Path::new("/proc/self/status").exists(),
        landlock: probe_landlock(),
    }
}

fn probe_user_namespaces() -> bool {
    if !Path::new("/proc/self/ns/user").exists() {
        return false;
    }
    if let Ok(s) = fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        if s.trim() == "0" {
            return false;
        }
    }
    true
}

fn probe_cgroups_v2() -> bool {
    fs::read_to_string("/proc/mounts")
        .map(|s| s.lines().any(|l| l.contains("cgroup2")))
        .unwrap_or(false)
}

fn probe_landlock() -> Option<u32> {
    use landlock::{Access, AccessFs, Ruleset, RulesetAttr, ABI};
    let abi = ABI::V1;
    if Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .is_ok()
    {
        Some(1)
    } else {
        None
    }
}
