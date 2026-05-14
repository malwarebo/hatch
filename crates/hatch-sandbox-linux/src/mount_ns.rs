use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use hatch_core::CompiledPolicy;
use rustix::fs::{mkdir, Mode};
use rustix::mount::{
    mount, mount_bind, mount_remount, MountFlags, MountPropagationFlags, UnmountFlags,
};
use rustix::process::pivot_root;

pub struct MountPlan {
    pub root: PathBuf,
}

pub fn build_rootfs(policy: &CompiledPolicy, root: &Path) -> Result<MountPlan> {
    std::fs::create_dir_all(root)?;
    let dirs = [
        "bin",
        "lib",
        "lib64",
        "sbin",
        "usr",
        "etc",
        "etc/ssl",
        "etc/ca-certificates",
        "tmp",
        "proc",
        "sys",
        "dev",
        "home",
    ];
    for d in dirs {
        let p = root.join(d);
        std::fs::create_dir_all(&p)?;
    }

    std::fs::write(
        root.join("etc/hosts"),
        "127.0.0.1 localhost\n::1 localhost\n",
    )?;
    std::fs::write(root.join("etc/resolv.conf"), "nameserver 127.0.0.1\n")?;
    std::fs::write(root.join("etc/nsswitch.conf"), "hosts: files dns\n")?;

    bind_ro(root, "/usr")?;
    if Path::new("/bin").exists() {
        bind_ro(root, "/bin")?;
    }
    if Path::new("/lib").exists() {
        bind_ro(root, "/lib")?;
    }
    if Path::new("/lib64").exists() {
        bind_ro(root, "/lib64")?;
    }
    if Path::new("/sbin").exists() {
        bind_ro(root, "/sbin")?;
    }
    if Path::new("/etc/ssl").exists() {
        bind_ro(root, "/etc/ssl")?;
    }
    if Path::new("/etc/ca-certificates").exists() {
        bind_ro(root, "/etc/ca-certificates")?;
    }

    let tmp = root.join("tmp");
    let _ = mount("tmpfs", &tmp, "tmpfs", MountFlags::empty(), "size=64m");

    for path in &policy.resolved_paths_read {
        if !path.exists() {
            continue;
        }
        let target = root.join(path.strip_prefix("/").unwrap_or(path));
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if path.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else {
            std::fs::write(&target, b"")?;
        }
        mount_bind(path, &target).with_context(|| format!("bind ro {path:?}"))?;
        mount_remount(&target, MountFlags::RDONLY, "")
            .with_context(|| format!("remount ro {target:?}"))?;
    }

    for path in &policy.resolved_paths_write {
        if !path.exists() {
            continue;
        }
        let target = root.join(path.strip_prefix("/").unwrap_or(path));
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if path.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else {
            std::fs::write(&target, b"")?;
        }
        mount_bind(path, &target).with_context(|| format!("bind rw {path:?}"))?;
    }

    Ok(MountPlan {
        root: root.to_path_buf(),
    })
}

pub fn pivot_into(root: &Path) -> Result<()> {
    let old_root = root.join(".pivot_old");
    let _ = mkdir(&old_root, Mode::from_raw_mode(0o700));
    rustix::mount::mount_change("/", MountPropagationFlags::SLAVE)
        .map_err(|e| anyhow!("propagation: {e}"))?;
    pivot_root(root, &old_root).map_err(|e| anyhow!("pivot_root: {e}"))?;
    std::env::set_current_dir("/").context("chdir /")?;
    rustix::mount::unmount("/.pivot_old", UnmountFlags::DETACH)
        .map_err(|e| anyhow!("detach old_root: {e}"))?;
    let _ = std::fs::remove_dir("/.pivot_old");
    Ok(())
}

fn bind_ro(root: &Path, src: &str) -> Result<()> {
    let target = root.join(src.strip_prefix('/').unwrap_or(src));
    std::fs::create_dir_all(&target)?;
    mount_bind(src, &target).with_context(|| format!("bind {src}"))?;
    mount_remount(&target, MountFlags::RDONLY, "")
        .with_context(|| format!("remount ro {target:?}"))?;
    Ok(())
}
