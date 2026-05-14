use hatch_core::CompiledPolicy;
use tracing::warn;

use crate::{
    build_command, next_id, BackendKind, Capabilities, Sandbox, SandboxError, SandboxedProcess,
};

pub struct StubBackend;

impl StubBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StubBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox for StubBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Stub
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }

    fn spawn(&self, policy: &CompiledPolicy) -> Result<SandboxedProcess, SandboxError> {
        warn!(
            target: "hatch::sandbox::stub",
            server = policy.manifest.name.as_str(),
            "spawning unsandboxed via stub backend; isolation guarantees not in effect"
        );
        let mut cmd = build_command(policy)?;
        let mut child = cmd.spawn()?;
        let pid = child.id().unwrap_or(0);
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        Ok(SandboxedProcess {
            id: next_id(),
            pid,
            backend: BackendKind::Stub,
            child,
            stdin,
            stdout,
            stderr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hatch_core::{compile::compile, manifest::Manifest, template::TemplateContext};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn fixture_for(program: &str) -> Manifest {
        let toml = format!(
            r#"
schema_version = "1.0"
name = "stubtest"
version = "0.1.0"
description = "stub backend smoke test"
[command]
program = "{program}"
args = []
[network]
allow_https = []
allow_dns = []
[filesystem]
read = []
write = []
tmpfs = ["/tmp"]
[env]
passthrough = []
[exec]
allow_subprocess = false
allow_binaries = []
[resources]
memory_mb = 64
cpu_percent = 10
pids_max = 10
nofile = 32
tool_call_timeout_seconds = 30
[tool_policy]
require_approval = []
deny = []
[platform.linux]
seccomp_preset = "strict"
landlock = true
[platform.macos]
endpoint_security = false
"#
        );
        Manifest::parse_str(&toml).unwrap()
    }

    #[tokio::test]
    async fn stub_spawns_and_echoes() {
        let cat = if std::path::Path::new("/bin/cat").exists() {
            "/bin/cat"
        } else {
            "/usr/bin/cat"
        };
        let m = fixture_for(cat);
        let policy = compile(&m, &TemplateContext::from_env()).unwrap();
        let backend = StubBackend::new();
        let mut sp = backend.spawn(&policy).unwrap();

        let mut stdin = sp.stdin.take().unwrap();
        let mut stdout = sp.stdout.take().unwrap();
        stdin.write_all(b"hello\n").await.unwrap();
        drop(stdin);

        let mut buf = String::new();
        stdout.read_to_string(&mut buf).await.unwrap();
        assert_eq!(buf, "hello\n");

        let status = sp.child.wait().await.unwrap();
        assert!(status.success());
    }
}
