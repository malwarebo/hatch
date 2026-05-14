#![deny(clippy::all)]

pub mod stub;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use std::process::Stdio;

use hatch_core::CompiledPolicy;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("backend {0:?} is not supported on this platform")]
    Unsupported(String),
    #[error("spawn: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("policy invalid for this backend: {0}")]
    InvalidPolicy(String),
    #[error("backend: {0}")]
    Backend(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Stub,
    Linux,
    Macos,
}

impl BackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BackendKind::Stub => "stub",
            BackendKind::Linux => "linux",
            BackendKind::Macos => "macos",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Capabilities {
    pub seccomp: bool,
    pub landlock: bool,
    pub endpoint_security: bool,
    pub network_namespace: bool,
    pub mount_namespace: bool,
}

pub trait Sandbox: Send + Sync {
    fn kind(&self) -> BackendKind;
    fn capabilities(&self) -> Capabilities;
    fn spawn(&self, policy: &CompiledPolicy) -> Result<SandboxedProcess, SandboxError>;
}

pub struct SandboxedProcess {
    pub id: String,
    pub pid: u32,
    pub backend: BackendKind,
    pub child: Child,
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
}

#[derive(Debug, Clone, Default)]
pub struct BackendOptions {
    pub runtime_dir: Option<std::path::PathBuf>,
    pub proxy_port: u16,
    pub dns_port: u16,
    pub allow_real_backend: bool,
}

pub fn default_backend() -> Box<dyn Sandbox> {
    Box::new(stub::StubBackend::new())
}

pub fn select_backend(opts: BackendOptions) -> Box<dyn Sandbox> {
    if !opts.allow_real_backend {
        return Box::new(stub::StubBackend::new());
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(rt) = opts.runtime_dir.clone() {
            let backend = linux::RealLinuxBackend::new(rt, opts.proxy_port, opts.dns_port);
            return Box::new(backend);
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(rt) = opts.runtime_dir.clone() {
            let backend = macos::RealMacosBackend::new(rt, opts.proxy_port, opts.dns_port);
            return Box::new(backend);
        }
    }
    let _ = opts;
    Box::new(stub::StubBackend::new())
}

pub(crate) fn build_command(policy: &CompiledPolicy) -> Result<Command, SandboxError> {
    let m = &policy.manifest;
    let mut cmd = Command::new(&m.command.program);
    cmd.args(&m.command.args);

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

    if let Some(wd) = &m.command.working_dir {
        if !wd.is_empty() {
            cmd.current_dir(wd);
        }
    }

    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    Ok(cmd)
}

pub(crate) fn next_id() -> String {
    Uuid::new_v4().to_string()
}
