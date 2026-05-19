use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use hatch_audit::{EventBuilder, EventType};
use hatch_core::compile::CompiledPolicy;
use hatch_core::{compile, template::TemplateContext, Manifest};
use hatch_proxy::ProxyRegistration;
use hatch_sandbox::{select_backend, BackendOptions, SandboxedProcess};
use hatch_state::RunningServerRow;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::manifests;
use crate::state_layer::DaemonState;

pub struct RunningServer {
    pub id: String,
    pub manifest_name: String,
    pub pid: u32,
    pub backend: String,
    pub policy: Arc<CompiledPolicy>,
    pub stdin_tx: mpsc::Sender<StdinEvent>,
    pub stdout_rx: Arc<Mutex<Option<mpsc::Receiver<Vec<u8>>>>>,
    pub stderr_rx: Arc<Mutex<Option<mpsc::Receiver<Vec<u8>>>>>,
    pub exit_rx: Arc<Mutex<Option<oneshot::Receiver<Option<i32>>>>>,
}

pub enum StdinEvent {
    Bytes(Vec<u8>),
    Eof,
}

#[derive(Default)]
pub struct Registry {
    inner: RwLock<HashMap<String, Arc<RunningServer>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert(&self, srv: Arc<RunningServer>) {
        self.inner.write().await.insert(srv.id.clone(), srv);
    }

    pub async fn get(&self, id: &str) -> Option<Arc<RunningServer>> {
        self.inner.read().await.get(id).cloned()
    }

    pub async fn remove(&self, id: &str) {
        self.inner.write().await.remove(id);
    }

    pub async fn all(&self) -> Vec<Arc<RunningServer>> {
        self.inner.read().await.values().cloned().collect()
    }

    pub async fn find_by_name(&self, name: &str) -> Option<Arc<RunningServer>> {
        self.inner
            .read()
            .await
            .values()
            .find(|s| s.manifest_name == name)
            .cloned()
    }
}

pub struct Runner {
    pub state: Arc<DaemonState>,
    pub registry: Arc<Registry>,
}

impl Runner {
    pub fn new(state: Arc<DaemonState>, registry: Arc<Registry>) -> Self {
        Self { state, registry }
    }

    pub async fn spawn(&self, name: &str, host: Option<String>) -> Result<Arc<RunningServer>> {
        let manifest: Manifest = manifests::fetch(&self.state, name)?;
        let mut ctx = TemplateContext::from_env();
        ctx.set_runtime_dirs(
            self.state.paths.runtime_dir.to_string_lossy().as_ref(),
            self.state.paths.state_dir.to_string_lossy().as_ref(),
        );
        let policy_compiled =
            compile::compile(&manifest, &ctx).map_err(|e| anyhow!("compile: {e}"))?;
        let policy = Arc::new(policy_compiled);

        let backend = select_backend(BackendOptions {
            runtime_dir: Some(self.state.paths.runtime_dir.clone()),
            proxy_port: self.state.proxy_port,
            dns_port: self.state.dns_port,
            allow_real_backend: self.state.real_sandbox,
        });
        let backend_kind = backend.kind().as_str().to_string();
        let mut sp: SandboxedProcess = backend.spawn(&policy).context("sandbox spawn")?;
        info!(
            target: "hatch::daemon::runner",
            server = name,
            backend = backend_kind.as_str(),
            pid = sp.pid,
            "sandboxed server spawned"
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let id = Uuid::new_v4().to_string();

        self.state.store.put_running(&RunningServerRow {
            id: id.clone(),
            manifest_name: manifest.name.clone(),
            manifest_version: manifest.version.clone(),
            host: host.clone(),
            pid: Some(sp.pid as i64),
            sandbox_backend: backend_kind.clone(),
            sandbox_id: sp.id.clone(),
            started_at: now,
            status: "running".into(),
        })?;

        self.state.record_audit(
            EventBuilder::new(EventType::ServerSpawn)
                .server(&manifest.name)
                .server_id(&id)
                .field("manifest_version", manifest.version.clone())
                .field("sandbox_backend", backend_kind.clone())
                .field("pid", sp.pid)
                .field(
                    "host",
                    host.clone().unwrap_or_else(|| "unknown".to_string()),
                ),
        );

        let (stdin_tx, stdin_rx) = mpsc::channel::<StdinEvent>(64);
        let (stdout_tx, stdout_rx) = mpsc::channel::<Vec<u8>>(64);
        let (stderr_tx, stderr_rx) = mpsc::channel::<Vec<u8>>(64);
        let (exit_tx, exit_rx) = oneshot::channel::<Option<i32>>();

        let stdin = sp.stdin.take();
        let stdout = sp.stdout.take();
        let stderr = sp.stderr.take();
        let mut child = sp.child;

        if let Some(stdin) = stdin {
            tokio::spawn(forward_stdin(stdin, stdin_rx));
        }
        if let Some(stdout) = stdout {
            tokio::spawn(forward_pipe(stdout, stdout_tx, "stdout"));
        }
        if let Some(stderr) = stderr {
            tokio::spawn(forward_pipe_err(stderr, stderr_tx));
        }

        let waiter_state = Arc::clone(&self.state);
        let waiter_registry = Arc::clone(&self.registry);
        let waiter_id = id.clone();
        let waiter_name = policy.manifest.name.clone();
        tokio::spawn(async move {
            let status = match child.wait().await {
                Ok(s) => s.code(),
                Err(e) => {
                    error!(target: "hatch::daemon::runner", "wait: {e}");
                    None
                }
            };
            let _ = waiter_state
                .store
                .set_status(&waiter_id, "exited")
                .map_err(|e| warn!(target: "hatch::daemon::runner", "set_status: {e}"));
            waiter_state.record_audit(
                EventBuilder::new(EventType::ServerExit)
                    .server(&waiter_name)
                    .server_id(&waiter_id)
                    .field("exit_code", status.unwrap_or(-1)),
            );
            waiter_state.proxy_registry.deregister(&waiter_id).await;
            waiter_registry.remove(&waiter_id).await;
            let _ = exit_tx.send(status);
        });

        let proxy_reg = ProxyRegistration {
            server_id: id.clone(),
            server_name: manifest.name.clone(),
            allow: Arc::new(policy.network_allow.clone()),
            rate_limit_mbps: manifest.network.rate_limit_mbps,
            max_bytes_per_connection: manifest
                .network
                .max_bytes_per_connection_mb
                .map(|m| m * 1024 * 1024),
        };
        self.state.proxy_registry.register(proxy_reg).await;

        let running = Arc::new(RunningServer {
            id: id.clone(),
            manifest_name: manifest.name,
            pid: sp.pid,
            backend: backend_kind,
            policy: Arc::clone(&policy),
            stdin_tx,
            stdout_rx: Arc::new(Mutex::new(Some(stdout_rx))),
            stderr_rx: Arc::new(Mutex::new(Some(stderr_rx))),
            exit_rx: Arc::new(Mutex::new(Some(exit_rx))),
        });
        self.registry.insert(Arc::clone(&running)).await;
        Ok(running)
    }

    pub async fn stop(&self, target: &str) -> Result<()> {
        let server = match self.registry.get(target).await {
            Some(s) => s,
            None => self
                .registry
                .find_by_name(target)
                .await
                .ok_or_else(|| anyhow!("no running server {target}"))?,
        };
        let _ = server.stdin_tx.send(StdinEvent::Eof).await;
        let _ = nix_kill(server.pid);
        self.state.store.set_status(&server.id, "exiting")?;
        Ok(())
    }
}

#[cfg(unix)]
fn nix_kill(pid: u32) -> Result<()> {
    if pid == 0 {
        return Ok(());
    }
    use rustix::process::{kill_process, Pid, Signal};
    if let Some(rpid) = Pid::from_raw(pid as i32) {
        let _ = kill_process(rpid, Signal::TERM);
    }
    Ok(())
}

#[cfg(not(unix))]
fn nix_kill(_pid: u32) -> Result<()> {
    Ok(())
}

async fn forward_stdin(mut stdin: ChildStdin, mut rx: mpsc::Receiver<StdinEvent>) {
    while let Some(ev) = rx.recv().await {
        match ev {
            StdinEvent::Bytes(b) => {
                if let Err(e) = stdin.write_all(&b).await {
                    debug!(target: "hatch::daemon::runner", "stdin write: {e}");
                    return;
                }
                if let Err(e) = stdin.flush().await {
                    debug!(target: "hatch::daemon::runner", "stdin flush: {e}");
                    return;
                }
            }
            StdinEvent::Eof => return,
        }
    }
}

async fn forward_pipe(mut pipe: ChildStdout, tx: mpsc::Sender<Vec<u8>>, label: &'static str) {
    let mut buf = [0u8; 4096];
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => {
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                debug!(target: "hatch::daemon::runner", "{label} read: {e}");
                return;
            }
        }
    }
}

async fn forward_pipe_err(mut pipe: ChildStderr, tx: mpsc::Sender<Vec<u8>>) {
    let mut buf = [0u8; 4096];
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => {
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                debug!(target: "hatch::daemon::runner", "stderr read: {e}");
                return;
            }
        }
    }
}
