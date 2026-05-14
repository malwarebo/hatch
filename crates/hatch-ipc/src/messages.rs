use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InstallSource {
    File {
        path: String,
    },
    Registry {
        name: String,
        version: Option<String>,
    },
    Git {
        url: String,
        git_ref: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RememberMode {
    Once,
    Session,
    ManifestVersion,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    pub server: Option<String>,
    pub event_type: Option<String>,
    pub since_seconds: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientRequest {
    DaemonStatus,
    DaemonStop,
    ListManifests,
    ListRunning,
    Install {
        source: InstallSource,
        allow_unsigned: bool,
    },
    Uninstall {
        name: String,
    },
    SpawnManual {
        name: String,
    },
    Stop {
        target: String,
    },
    Inspect {
        target: String,
    },
    Audit {
        filter: AuditFilter,
        follow: bool,
    },
    Approve {
        approval_id: String,
        remember: RememberMode,
    },
    Deny {
        approval_id: String,
    },

    SpawnSandboxed {
        name: String,
        host: String,
    },
    ShimStdin {
        server_id: String,
        data: Vec<u8>,
    },
    ShimStdinEof {
        server_id: String,
    },
    PolicyQuery {
        server_id: String,
        tool: String,
        args: serde_json::Value,
    },
    Heartbeat,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Internal = 1,
    BadRequest = 2,
    NotFound = 11,
    ManifestInvalid = 12,
    SignatureFailed = 13,
    ApprovalTimeout = 14,
    SpawnFailed = 15,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestSummary {
    pub name: String,
    pub version: String,
    pub source: String,
    pub signature_verified: bool,
    pub risk_score: u32,
    pub installed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningServerSummary {
    pub id: String,
    pub manifest_name: String,
    pub manifest_version: String,
    pub host: Option<String>,
    pub pid: u32,
    pub sandbox_backend: String,
    pub started_at: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventEnvelope {
    pub ts: String,
    pub event_id: String,
    pub server: String,
    pub server_id: Option<String>,
    pub host: Option<String>,
    pub event: String,
    pub fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny {
        reason: String,
    },
    RequireApproval {
        approval_id: String,
        timeout_seconds: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonResponse {
    Ok,
    Error {
        code: ErrorCode,
        message: String,
    },
    Manifests {
        items: Vec<ManifestSummary>,
    },
    RunningServers {
        items: Vec<RunningServerSummary>,
    },
    Spawned {
        server_id: String,
        sandbox_backend: String,
    },
    AuditEvents {
        events: Vec<AuditEventEnvelope>,
        more_pending: bool,
    },
    PolicyDecision {
        decision: PolicyDecision,
    },
    DaemonStatus {
        uptime_seconds: u64,
        running_servers: usize,
        version: String,
    },

    ShimStdoutChunk {
        server_id: String,
        data: Vec<u8>,
    },
    ShimStderrChunk {
        server_id: String,
        data: Vec<u8>,
    },
    ShimServerExit {
        server_id: String,
        exit_code: Option<i32>,
    },
    Heartbeat,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_source_round_trip() {
        let src = InstallSource::File {
            path: "/x/y.toml".into(),
        };
        let j = serde_json::to_string(&src).unwrap();
        let back: InstallSource = serde_json::from_str(&j).unwrap();
        match back {
            InstallSource::File { path } => assert_eq!(path, "/x/y.toml"),
            _ => panic!(),
        }
    }

    #[test]
    fn policy_decision_round_trip() {
        let d = PolicyDecision::RequireApproval {
            approval_id: "abc".into(),
            timeout_seconds: 60,
        };
        let j = serde_json::to_string(&d).unwrap();
        let back: PolicyDecision = serde_json::from_str(&j).unwrap();
        match back {
            PolicyDecision::RequireApproval {
                approval_id,
                timeout_seconds,
            } => {
                assert_eq!(approval_id, "abc");
                assert_eq!(timeout_seconds, 60);
            }
            _ => panic!(),
        }
    }
}
