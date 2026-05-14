use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{Context, Result};
use hatch_core::CompiledPolicy;
use thiserror::Error;
use tokio::process::{Child, Command};
use uuid::Uuid;

use crate::{cgroups, netns, LinuxCapabilities};

#[derive(Debug, Error)]
pub enum LinuxBackendError {
    #[error("missing kernel capability: {0}")]
    MissingCapability(&'static str),
    #[error("spawn: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("setup: {0}")]
    Setup(#[from] anyhow::Error),
}

pub struct LinuxBackend {
    pub runtime_dir: PathBuf,
    pub proxy_port: u16,
    pub dns_port: u16,
    pub capabilities: LinuxCapabilities,
}

pub struct LinuxSpawned {
    pub id: String,
    pub pid: u32,
    pub child: Child,
    pub stdin: Option<tokio::process::ChildStdin>,
    pub stdout: Option<tokio::process::ChildStdout>,
    pub stderr: Option<tokio::process::ChildStderr>,
    pub netns_name: String,
    pub cgroup_path: PathBuf,
}

impl LinuxBackend {
    pub fn new(runtime_dir: PathBuf, proxy_port: u16, dns_port: u16) -> Self {
        let capabilities = crate::capabilities::detect_capabilities();
        Self {
            runtime_dir,
            proxy_port,
            dns_port,
            capabilities,
        }
    }

    pub fn spawn(&self, policy: &CompiledPolicy) -> Result<LinuxSpawned, LinuxBackendError> {
        if !self.capabilities.user_namespaces {
            return Err(LinuxBackendError::MissingCapability("user namespaces"));
        }
        if !self.capabilities.cgroups_v2 {
            return Err(LinuxBackendError::MissingCapability("cgroups v2"));
        }

        let id = Uuid::new_v4().to_string();
        let server_runtime = self.runtime_dir.join(&id);
        std::fs::create_dir_all(&server_runtime).context("create runtime dir")?;

        let cgroup = cgroups::create_for(policy, &id).context("cgroups")?;
        let netns_handle =
            netns::create_for(&id, self.proxy_port, self.dns_port).context("netns")?;

        let m = &policy.manifest;
        let mut cmd = Command::new("ip");
        cmd.arg("netns")
            .arg("exec")
            .arg(&netns_handle.name)
            .arg("unshare")
            .arg("--user")
            .arg("--mount")
            .arg("--pid")
            .arg("--fork")
            .arg("--map-root-user")
            .arg("--")
            .arg(&m.command.program)
            .args(&m.command.args);

        cmd.env_clear();
        for k in &m.env.passthrough {
            if let Ok(v) = std::env::var(k) {
                cmd.env(k, v);
            }
        }
        for (k, v) in &policy.resolved_env {
            cmd.env(k, v);
        }
        for k in &m.env.unset {
            cmd.env_remove(k);
        }
        cmd.env("HATCH_SERVER_ID", &id);
        cmd.env("HATCH_RUNTIME_DIR", &server_runtime);

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| {
            netns::destroy(&netns_handle);
            cgroup.cleanup();
            LinuxBackendError::Spawn(e)
        })?;
        let pid = child.id().unwrap_or(0);
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        Ok(LinuxSpawned {
            id,
            pid,
            child,
            stdin,
            stdout,
            stderr,
            netns_name: netns_handle.name,
            cgroup_path: cgroup.path,
        })
    }
}
