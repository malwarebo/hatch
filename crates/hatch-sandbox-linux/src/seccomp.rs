use anyhow::{anyhow, Result};
use hatch_core::manifest::SeccompPreset;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
use std::collections::BTreeMap;

const ALWAYS_DENIED: &[&str] = &[
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "ptrace",
    "bpf",
    "keyctl",
    "add_key",
    "request_key",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "perf_event_open",
    "userfaultfd",
    "unshare",
    "setns",
    "swapon",
    "swapoff",
    "reboot",
    "sethostname",
    "setdomainname",
];

const STRICT_EXTRA_DENIED: &[&str] = &["execveat", "process_vm_readv", "process_vm_writev"];

pub struct SeccompProfile {
    pub program: BpfProgram,
}

pub fn compile(preset: SeccompPreset, allow_subprocess: bool) -> Result<SeccompProfile> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    for name in ALWAYS_DENIED {
        if let Some(n) = lookup_syscall(name) {
            rules.insert(n, vec![]);
        }
    }

    let mut strict = preset == SeccompPreset::Strict;
    if strict {
        for name in STRICT_EXTRA_DENIED {
            if let Some(n) = lookup_syscall(name) {
                rules.insert(n, vec![]);
            }
        }
        if !allow_subprocess {
            if let Some(n) = lookup_syscall("execve") {
                rules.insert(n, vec![]);
            }
        }
    } else {
        strict = false;
    }
    let _ = strict;

    let default_action = match preset {
        SeccompPreset::Permissive => SeccompAction::Allow,
        SeccompPreset::Default => SeccompAction::Allow,
        SeccompPreset::Strict => SeccompAction::Allow,
    };

    let filter = SeccompFilter::new(
        rules,
        default_action,
        SeccompAction::Errno(libc::EPERM as u32),
        target_arch(),
    )
    .map_err(|e| anyhow!("seccomp filter: {e}"))?;

    let program: BpfProgram = filter
        .try_into()
        .map_err(|e| anyhow!("seccomp compile: {e}"))?;
    Ok(SeccompProfile { program })
}

#[cfg(target_arch = "x86_64")]
fn target_arch() -> TargetArch {
    TargetArch::x86_64
}

#[cfg(target_arch = "aarch64")]
fn target_arch() -> TargetArch {
    TargetArch::aarch64
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn target_arch() -> TargetArch {
    TargetArch::x86_64
}

fn lookup_syscall(name: &str) -> Option<i64> {
    match name {
        "mount" => Some(libc::SYS_mount),
        "umount2" => Some(libc::SYS_umount2),
        "pivot_root" => Some(libc::SYS_pivot_root),
        "chroot" => Some(libc::SYS_chroot),
        "ptrace" => Some(libc::SYS_ptrace),
        "bpf" => Some(libc::SYS_bpf),
        "keyctl" => Some(libc::SYS_keyctl),
        "add_key" => Some(libc::SYS_add_key),
        "request_key" => Some(libc::SYS_request_key),
        "kexec_load" => Some(libc::SYS_kexec_load),
        "kexec_file_load" => Some(libc::SYS_kexec_file_load),
        "init_module" => Some(libc::SYS_init_module),
        "finit_module" => Some(libc::SYS_finit_module),
        "delete_module" => Some(libc::SYS_delete_module),
        "perf_event_open" => Some(libc::SYS_perf_event_open),
        "userfaultfd" => Some(libc::SYS_userfaultfd),
        "unshare" => Some(libc::SYS_unshare),
        "setns" => Some(libc::SYS_setns),
        "swapon" => Some(libc::SYS_swapon),
        "swapoff" => Some(libc::SYS_swapoff),
        "reboot" => Some(libc::SYS_reboot),
        "sethostname" => Some(libc::SYS_sethostname),
        "setdomainname" => Some(libc::SYS_setdomainname),
        "execve" => Some(libc::SYS_execve),
        "execveat" => Some(libc::SYS_execveat),
        "process_vm_readv" => Some(libc::SYS_process_vm_readv),
        "process_vm_writev" => Some(libc::SYS_process_vm_writev),
        _ => None,
    }
    .map(|n| n as i64)
}

pub fn apply(program: &BpfProgram) -> Result<()> {
    seccompiler::apply_filter(program).map_err(|e| anyhow!("apply seccomp: {e}"))
}
