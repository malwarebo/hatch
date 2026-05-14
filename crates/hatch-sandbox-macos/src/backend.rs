use std::path::PathBuf;
use std::process::Stdio;

use anyhow::Context;
use hatch_core::CompiledPolicy;
use thiserror::Error;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use uuid::Uuid;

use crate::{pf, profile, uid_pool::UidPool};

#[derive(Debug, Error)]
pub enum MacosBackendError {
    #[error("no sandbox UIDs available; run `sudo hatch install --system` first")]
    NoUids,
    #[error("spawn: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("setup: {0}")]
    Setup(#[from] anyhow::Error),
}

pub struct MacosBackend {
    pub runtime_dir: PathBuf,
    pub proxy_port: u16,
    pub dns_port: u16,
    pub uid_pool: UidPool,
    pub require_uid_pool: bool,
}

pub struct MacosSpawned {
    pub id: String,
    pub pid: u32,
    pub user: Option<String>,
    pub child: Child,
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    pub profile_path: PathBuf,
}

impl MacosBackend {
    pub fn new(runtime_dir: PathBuf, proxy_port: u16, dns_port: u16) -> Self {
        Self {
            runtime_dir,
            proxy_port,
            dns_port,
            uid_pool: UidPool::discover(),
            require_uid_pool: false,
        }
    }

    pub fn with_required_uid_pool(mut self, require: bool) -> Self {
        self.require_uid_pool = require;
        self
    }

    pub fn spawn(&self, policy: &CompiledPolicy) -> Result<MacosSpawned, MacosBackendError> {
        let id = Uuid::new_v4().to_string();
        let server_runtime = self.runtime_dir.join(&id);
        std::fs::create_dir_all(&server_runtime).context("create runtime")?;

        let user = self.uid_pool.checkout();
        if self.require_uid_pool && user.is_none() {
            return Err(MacosBackendError::NoUids);
        }

        let sb_profile = profile::render_sandbox_exec_profile(
            policy,
            &server_runtime.to_string_lossy(),
            self.proxy_port,
            self.dns_port,
        );
        let profile_path = server_runtime.join("profile.sb");
        std::fs::write(&profile_path, &sb_profile).context("write sandbox profile")?;

        if let Some(u) = user.as_ref() {
            let pf_rules =
                pf::generate_anchor(u, "127.0.0.1", self.proxy_port, "127.0.0.1", self.dns_port);
            if let Err(e) = pf::load_anchor(&id, &pf_rules) {
                tracing::warn!(target: "hatch::macos", "could not load PF anchor: {e}");
            }
        }

        let m = &policy.manifest;
        let mut cmd = Command::new("/usr/bin/sandbox-exec");
        cmd.arg("-f").arg(&profile_path).arg("--");
        cmd.arg(&m.command.program);
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
        cmd.env("HATCH_SERVER_ID", &id);
        cmd.env("HATCH_RUNTIME_DIR", &server_runtime);

        if let Some(wd) = &m.command.working_dir {
            if !wd.is_empty() {
                cmd.current_dir(wd);
            } else {
                cmd.current_dir(&server_runtime);
            }
        } else {
            cmd.current_dir(&server_runtime);
        }

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| {
            pf::unload_anchor(&id);
            MacosBackendError::Spawn(e)
        })?;
        let pid = child.id().unwrap_or(0);
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        Ok(MacosSpawned {
            id,
            pid,
            user,
            child,
            stdin,
            stdout,
            stderr,
            profile_path,
        })
    }

    pub fn cleanup_after_exit(&self, server_id: &str, user: Option<String>) {
        pf::unload_anchor(server_id);
        if let Some(u) = user {
            self.uid_pool.return_uid(u);
        }
    }
}
