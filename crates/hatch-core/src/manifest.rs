use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::CoreError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub license: Option<String>,

    pub command: CommandSpec,

    #[serde(default)]
    pub integrity: Option<IntegritySpec>,

    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub env: EnvPolicy,
    #[serde(default)]
    pub exec: ExecPolicy,
    pub resources: ResourceLimits,
    #[serde(default)]
    pub tool_policy: ToolPolicy,
    #[serde(default)]
    pub platform: PlatformOverrides,
    #[serde(default)]
    pub signature: Option<Signature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSpec {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntegritySpec {
    #[serde(default)]
    pub npm_package: Option<String>,
    #[serde(default)]
    pub npm_version: Option<String>,
    #[serde(default)]
    pub npm_integrity: Option<String>,
    #[serde(default)]
    pub pip_package: Option<String>,
    #[serde(default)]
    pub pip_version: Option<String>,
    #[serde(default)]
    pub pip_hash: Option<String>,
    #[serde(default)]
    pub git_repo: Option<String>,
    #[serde(default)]
    pub git_ref: Option<String>,
    #[serde(default)]
    pub git_commit: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub allow_https: Vec<String>,
    #[serde(default)]
    pub allow_dns: Vec<String>,
    #[serde(default)]
    pub allow_http: bool,
    #[serde(default)]
    pub rate_limit_mbps: Option<u32>,
    #[serde(default)]
    pub max_bytes_per_connection_mb: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub tmpfs: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvPolicy {
    #[serde(default)]
    pub passthrough: Vec<String>,
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub unset: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecPolicy {
    #[serde(default)]
    pub allow_subprocess: bool,
    #[serde(default)]
    pub allow_binaries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub memory_mb: u32,
    #[serde(default = "default_cpu_percent")]
    pub cpu_percent: u32,
    #[serde(default = "default_pids_max")]
    pub pids_max: u32,
    #[serde(default = "default_nofile")]
    pub nofile: u32,
    #[serde(default = "default_timeout")]
    pub tool_call_timeout_seconds: u32,
}

fn default_cpu_percent() -> u32 {
    50
}
fn default_pids_max() -> u32 {
    50
}
fn default_nofile() -> u32 {
    256
}
fn default_timeout() -> u32 {
    60
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolPolicy {
    #[serde(default)]
    pub require_approval: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default, rename = "rules")]
    pub rules: Vec<ToolRule>,
    #[serde(default)]
    pub response_filters: Vec<ResponseFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRule {
    pub tool: String,
    #[serde(default)]
    pub when: Option<String>,
    pub action: RuleActionStr,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleActionStr {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFilter {
    pub pattern: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformOverrides {
    #[serde(default)]
    pub linux: LinuxOverrides,
    #[serde(default)]
    pub macos: MacosOverrides,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxOverrides {
    #[serde(default)]
    pub seccomp_preset: SeccompPreset,
    #[serde(default = "default_landlock")]
    pub landlock: bool,
    #[serde(default)]
    pub extra_caps: Vec<String>,
}

impl Default for LinuxOverrides {
    fn default() -> Self {
        Self {
            seccomp_preset: SeccompPreset::default(),
            landlock: true,
            extra_caps: Vec::new(),
        }
    }
}

fn default_landlock() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SeccompPreset {
    Permissive,
    Default,
    #[default]
    Strict,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MacosOverrides {
    #[serde(default)]
    pub endpoint_security: bool,
    #[serde(default)]
    pub extra_sbpl: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub key_id: String,
    pub algorithm: String,
    pub sig: String,
    pub signed_at: String,
}

impl Manifest {
    pub fn parse_str(s: &str) -> Result<Self, CoreError> {
        let m: Manifest = toml::from_str(s)?;
        Ok(m)
    }

    pub fn parse_file(path: impl AsRef<Path>) -> Result<Self, CoreError> {
        let raw = std::fs::read_to_string(path)?;
        Self::parse_str(&raw)
    }

    pub fn fingerprint(&self) -> String {
        let mut m = self.clone();
        m.signature = None;
        let canon = serde_json::to_vec(&m).unwrap_or_default();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&canon);
        let hex = hasher.finalize().to_hex();
        format!("blake3:{hex}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: &str = r#"
schema_version = "1.0"
name = "example"
version = "0.1.0"
description = "Minimal manifest for testing"

[command]
program = "/bin/cat"
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
"#;

    #[test]
    fn parses_minimal() {
        let m = Manifest::parse_str(MIN).unwrap();
        assert_eq!(m.name, "example");
        assert_eq!(m.command.program, "/bin/cat");
        assert!(m.signature.is_none());
        assert_eq!(m.platform.linux.seccomp_preset, SeccompPreset::Strict);
    }

    #[test]
    fn fingerprint_ignores_signature() {
        let mut m = Manifest::parse_str(MIN).unwrap();
        let f1 = m.fingerprint();
        m.signature = Some(Signature {
            key_id: "k".into(),
            algorithm: "ed25519".into(),
            sig: "AA".into(),
            signed_at: "2026-01-01T00:00:00Z".into(),
        });
        let f2 = m.fingerprint();
        assert_eq!(f1, f2);
    }
}
