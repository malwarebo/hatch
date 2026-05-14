use std::path::PathBuf;

use hatch_core::CompiledPolicy;
use hatch_sandbox_linux::LinuxBackend;
use tracing::warn;

use crate::{BackendKind, Capabilities, Sandbox, SandboxError, SandboxedProcess};

pub struct RealLinuxBackend {
    inner: LinuxBackend,
}

impl RealLinuxBackend {
    pub fn new(runtime_dir: PathBuf, proxy_port: u16, dns_port: u16) -> Self {
        Self {
            inner: LinuxBackend::new(runtime_dir, proxy_port, dns_port),
        }
    }
}

impl Sandbox for RealLinuxBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Linux
    }

    fn capabilities(&self) -> Capabilities {
        let c = &self.inner.capabilities;
        Capabilities {
            seccomp: c.seccomp,
            landlock: c.landlock.is_some(),
            endpoint_security: false,
            network_namespace: c.net_namespaces,
            mount_namespace: c.mount_namespaces,
        }
    }

    fn spawn(&self, policy: &CompiledPolicy) -> Result<SandboxedProcess, SandboxError> {
        match self.inner.spawn(policy) {
            Ok(s) => Ok(SandboxedProcess {
                id: s.id,
                pid: s.pid,
                backend: BackendKind::Linux,
                child: s.child,
                stdin: s.stdin,
                stdout: s.stdout,
                stderr: s.stderr,
            }),
            Err(e) => {
                warn!(target: "hatch::sandbox::linux", "real backend failed: {e}");
                Err(SandboxError::Backend(format!("{e}")))
            }
        }
    }
}
