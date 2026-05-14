use std::path::PathBuf;

use hatch_core::CompiledPolicy;
use hatch_sandbox_macos::MacosBackend;
use tracing::warn;

use crate::{BackendKind, Capabilities, Sandbox, SandboxError, SandboxedProcess};

pub struct RealMacosBackend {
    inner: MacosBackend,
}

impl RealMacosBackend {
    pub fn new(runtime_dir: PathBuf, proxy_port: u16, dns_port: u16) -> Self {
        Self {
            inner: MacosBackend::new(runtime_dir, proxy_port, dns_port),
        }
    }
}

impl Sandbox for RealMacosBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Macos
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            seccomp: false,
            landlock: false,
            endpoint_security: false,
            network_namespace: false,
            mount_namespace: false,
        }
    }

    fn spawn(&self, policy: &CompiledPolicy) -> Result<SandboxedProcess, SandboxError> {
        match self.inner.spawn(policy) {
            Ok(s) => Ok(SandboxedProcess {
                id: s.id,
                pid: s.pid,
                backend: BackendKind::Macos,
                child: s.child,
                stdin: s.stdin,
                stdout: s.stdout,
                stderr: s.stderr,
            }),
            Err(e) => {
                warn!(target: "hatch::sandbox::macos", "real backend failed: {e}");
                Err(SandboxError::Backend(format!("{e}")))
            }
        }
    }
}
