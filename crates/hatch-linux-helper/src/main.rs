use std::path::PathBuf;
use std::process::ExitCode;

use hatch_linux_helper::HelperPolicy;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let policy_path = match args.next() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("hatch-linux-helper: usage: hatch-linux-helper <policy.json>");
            return ExitCode::from(64);
        }
    };
    let raw = match std::fs::read_to_string(&policy_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hatch-linux-helper: read {}: {e}", policy_path.display());
            return ExitCode::from(66);
        }
    };
    let policy: HelperPolicy = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("hatch-linux-helper: parse policy: {e}");
            return ExitCode::from(65);
        }
    };

    #[cfg(target_os = "linux")]
    {
        match imp::run_linux(policy) {
            Ok(never) => match never {},
            Err(e) => {
                eprintln!("hatch-linux-helper: {e}");
                ExitCode::from(1)
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
        eprintln!("hatch-linux-helper: this binary only runs on Linux");
        ExitCode::from(127)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use hatch_linux_helper::{HelperPolicy, SeccompPreset};
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    pub enum Never {}

    pub fn run_linux(policy: HelperPolicy) -> Result<Never, String> {
        if policy.apply_landlock {
            apply_landlock(&policy.read_paths, &policy.write_paths)?;
        }
        apply_seccomp(policy.seccomp_preset, policy.allow_subprocess)?;
        exec_program(&policy.program, &policy.args)
    }

    fn apply_landlock(
        read: &[std::path::PathBuf],
        write: &[std::path::PathBuf],
    ) -> Result<(), String> {
        use landlock::{
            Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
            RulesetStatus, ABI,
        };

        let abi = ABI::V1;
        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| format!("landlock handle_access: {e}"))?
            .create()
            .map_err(|e| format!("landlock create: {e}"))?;
        let read_access = AccessFs::from_read(abi);
        let write_access = AccessFs::from_all(abi);
        for path in read {
            match PathFd::new(path) {
                Ok(fd) => {
                    ruleset = ruleset
                        .add_rule(PathBeneath::new(fd, read_access))
                        .map_err(|e| format!("landlock add read rule {}: {e}", path.display()))?;
                }
                Err(e) => {
                    eprintln!(
                        "hatch-linux-helper: warning: landlock skip read {} ({e})",
                        path.display()
                    );
                }
            }
        }
        for path in write {
            match PathFd::new(path) {
                Ok(fd) => {
                    ruleset = ruleset
                        .add_rule(PathBeneath::new(fd, write_access))
                        .map_err(|e| format!("landlock add write rule {}: {e}", path.display()))?;
                }
                Err(e) => {
                    eprintln!(
                        "hatch-linux-helper: warning: landlock skip write {} ({e})",
                        path.display()
                    );
                }
            }
        }
        let status = ruleset
            .restrict_self()
            .map_err(|e| format!("landlock restrict_self: {e}"))?;
        match status.ruleset {
            RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced => Ok(()),
            RulesetStatus::NotEnforced => {
                eprintln!(
                    "hatch-linux-helper: warning: Landlock not enforced (kernel missing support)"
                );
                Ok(())
            }
        }
    }

    fn apply_seccomp(preset: SeccompPreset, allow_subprocess: bool) -> Result<(), String> {
        use seccompiler::{
            apply_filter, BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch,
        };
        use std::collections::BTreeMap;

        if matches!(preset, SeccompPreset::Permissive) {
            return Ok(());
        }

        let target = if cfg!(target_arch = "x86_64") {
            TargetArch::x86_64
        } else if cfg!(target_arch = "aarch64") {
            TargetArch::aarch64
        } else {
            return Ok(());
        };

        let mut denied: Vec<&str> = vec![
            "mount",
            "umount2",
            "pivot_root",
            "chroot",
            "swapon",
            "swapoff",
            "reboot",
            "kexec_load",
            "kexec_file_load",
            "init_module",
            "finit_module",
            "delete_module",
            "bpf",
            "perf_event_open",
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "userfaultfd",
            "keyctl",
            "add_key",
            "request_key",
        ];
        if matches!(preset, SeccompPreset::Strict) {
            denied.extend_from_slice(&[
                "unshare",
                "setns",
                "clone3",
                "mount_setattr",
                "open_tree",
                "move_mount",
                "fsopen",
                "fsconfig",
                "fsmount",
                "fspick",
            ]);
            if !allow_subprocess {
                denied.extend_from_slice(&["execve", "execveat"]);
            }
        }

        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for name in denied {
            if let Some(num) = libc_syscall_number(name) {
                rules.insert(num, Vec::new());
            }
        }

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            target,
        )
        .map_err(|e| format!("seccomp filter: {e}"))?;
        let program: BpfProgram = filter
            .try_into()
            .map_err(|e| format!("seccomp compile: {e}"))?;
        apply_filter(&program).map_err(|e| format!("seccomp apply: {e}"))?;
        Ok(())
    }

    fn libc_syscall_number(name: &str) -> Option<i64> {
        match name {
            "mount" => Some(libc::SYS_mount),
            "umount2" => Some(libc::SYS_umount2),
            "pivot_root" => Some(libc::SYS_pivot_root),
            "chroot" => Some(libc::SYS_chroot),
            "swapon" => Some(libc::SYS_swapon),
            "swapoff" => Some(libc::SYS_swapoff),
            "reboot" => Some(libc::SYS_reboot),
            "kexec_load" => Some(libc::SYS_kexec_load),
            "kexec_file_load" => Some(libc::SYS_kexec_file_load),
            "init_module" => Some(libc::SYS_init_module),
            "finit_module" => Some(libc::SYS_finit_module),
            "delete_module" => Some(libc::SYS_delete_module),
            "bpf" => Some(libc::SYS_bpf),
            "perf_event_open" => Some(libc::SYS_perf_event_open),
            "ptrace" => Some(libc::SYS_ptrace),
            "process_vm_readv" => Some(libc::SYS_process_vm_readv),
            "process_vm_writev" => Some(libc::SYS_process_vm_writev),
            "userfaultfd" => Some(libc::SYS_userfaultfd),
            "keyctl" => Some(libc::SYS_keyctl),
            "add_key" => Some(libc::SYS_add_key),
            "request_key" => Some(libc::SYS_request_key),
            "unshare" => Some(libc::SYS_unshare),
            "setns" => Some(libc::SYS_setns),
            "clone3" => Some(libc::SYS_clone3),
            "mount_setattr" => Some(libc::SYS_mount_setattr),
            "open_tree" => Some(libc::SYS_open_tree),
            "move_mount" => Some(libc::SYS_move_mount),
            "fsopen" => Some(libc::SYS_fsopen),
            "fsconfig" => Some(libc::SYS_fsconfig),
            "fsmount" => Some(libc::SYS_fsmount),
            "fspick" => Some(libc::SYS_fspick),
            "execve" => Some(libc::SYS_execve),
            "execveat" => Some(libc::SYS_execveat),
            _ => None,
        }
    }

    fn exec_program(
        program: &std::path::Path,
        args: &[std::ffi::OsString],
    ) -> Result<Never, String> {
        let cprog = CString::new(program.as_os_str().as_bytes())
            .map_err(|e| format!("program path contains NUL: {e}"))?;
        let mut argv: Vec<CString> = Vec::with_capacity(args.len() + 1);
        argv.push(cprog.clone());
        for a in args {
            argv.push(CString::new(a.as_bytes()).map_err(|e| format!("argv contains NUL: {e}"))?);
        }
        let argv_ptrs: Vec<*const libc::c_char> = argv
            .iter()
            .map(|c| c.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        unsafe {
            libc::execvp(cprog.as_ptr(), argv_ptrs.as_ptr());
        }
        Err(format!(
            "execvp {} failed: {}",
            program.display(),
            std::io::Error::last_os_error()
        ))
    }
}
