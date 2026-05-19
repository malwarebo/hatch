use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use hatch_core::CompiledPolicy;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

pub struct CgroupHandle {
    pub path: PathBuf,
}

impl CgroupHandle {
    pub fn cleanup(&self) {
        let _ = fs::remove_dir(&self.path);
    }
}

pub fn create_for(policy: &CompiledPolicy, server_id: &str) -> Result<CgroupHandle> {
    let path = Path::new(CGROUP_ROOT)
        .join("hatch.slice")
        .join(format!("server-{server_id}.scope"));
    fs::create_dir_all(&path).with_context(|| format!("create cgroup {path:?}"))?;

    let limits = &policy.manifest.resources;
    write_value(
        &path,
        "memory.max",
        (limits.memory_mb as u64 * 1024 * 1024).to_string(),
    )?;
    let _ = write_value(&path, "memory.swap.max", "0");
    write_value(&path, "pids.max", limits.pids_max.to_string())?;
    let weight = (limits.cpu_percent as u64).clamp(1, 100) * 10;
    let _ = write_value(&path, "cpu.weight", weight.to_string());
    Ok(CgroupHandle { path })
}

fn write_value(dir: &Path, file: &str, value: impl AsRef<str>) -> Result<()> {
    let target = dir.join(file);
    fs::write(&target, value.as_ref()).map_err(|e| anyhow!("write {target:?}: {e}"))
}

pub fn attach_pid(cgroup_dir: &Path, pid: u32) -> Result<()> {
    let target = cgroup_dir.join("cgroup.procs");
    fs::write(&target, pid.to_string()).map_err(|e| anyhow!("attach pid to {target:?}: {e}"))
}
