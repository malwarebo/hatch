use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hatch_ipc::RememberMode;
use tokio::sync::{oneshot, Mutex};
use uuid::Uuid;

pub const REMEMBER_MANIFEST_VERSION_SECONDS: i64 = 60 * 60 * 24 * 30;

#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Deny,
    Timeout,
}

pub struct Pending {
    pub server_name: String,
    pub tool: String,
    pub args_hash: String,
    pub sender: oneshot::Sender<Decision>,
}

#[derive(Debug, Clone)]
pub struct RememberedDecision {
    pub decision: Decision,
    pub deadline_secs: Option<i64>,
}

type RememberedMap = HashMap<String, RememberedDecision>;

#[derive(Default, Clone)]
pub struct ApprovalBroker {
    inner: Arc<Mutex<HashMap<String, Pending>>>,
    remembered: Arc<Mutex<RememberedMap>>,
}

impl ApprovalBroker {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn check_remembered(
        &self,
        server_name: &str,
        tool: &str,
        args_hash: &str,
    ) -> Option<Decision> {
        let key = composite_key(server_name, tool, args_hash);
        let now = now_secs();
        let mut guard = self.remembered.lock().await;
        if let Some(record) = guard.get(&key).cloned() {
            if let Some(deadline) = record.deadline_secs {
                if deadline <= now {
                    guard.remove(&key);
                    return None;
                }
            }
            return Some(record.decision);
        }
        None
    }

    pub async fn request(
        &self,
        server_name: String,
        tool: String,
        args_hash: String,
    ) -> (String, oneshot::Receiver<Decision>) {
        let id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        let pending = Pending {
            server_name,
            tool,
            args_hash,
            sender: tx,
        };
        self.inner.lock().await.insert(id.clone(), pending);
        (id, rx)
    }

    pub async fn approve(&self, id: &str, remember: RememberMode) -> Option<ApproveResult> {
        let pending = self.inner.lock().await.remove(id)?;
        let server = pending.server_name.clone();
        let tool = pending.tool.clone();
        let args_hash = pending.args_hash.clone();
        let composite = composite_key(&server, &tool, &args_hash);

        let deadline_secs = match remember {
            RememberMode::Once => None,
            RememberMode::Session => Some(None),
            RememberMode::ManifestVersion => {
                Some(Some(now_secs() + REMEMBER_MANIFEST_VERSION_SECONDS))
            }
        };
        if let Some(maybe_deadline) = deadline_secs {
            self.remembered.lock().await.insert(
                composite.clone(),
                RememberedDecision {
                    decision: Decision::Allow,
                    deadline_secs: maybe_deadline,
                },
            );
        }
        let _ = pending.sender.send(Decision::Allow);
        Some(ApproveResult {
            server,
            tool,
            args_hash,
            persisted_deadline: deadline_secs,
        })
    }

    pub async fn deny(&self, id: &str) -> Option<(String, String, String)> {
        let pending = self.inner.lock().await.remove(id)?;
        let key = (
            pending.server_name.clone(),
            pending.tool.clone(),
            pending.args_hash.clone(),
        );
        let composite = composite_key(&key.0, &key.1, &key.2);
        self.remembered.lock().await.remove(&composite);
        let _ = pending.sender.send(Decision::Deny);
        Some(key)
    }

    pub async fn timeout(&self, id: &str) {
        if let Some(pending) = self.inner.lock().await.remove(id) {
            let _ = pending.sender.send(Decision::Timeout);
        }
    }

    pub async fn restore_remembered(&self, items: Vec<(String, String, String, Option<i64>)>) {
        let now = now_secs();
        let mut guard = self.remembered.lock().await;
        for (server, tool, args_hash, deadline) in items {
            if let Some(d) = deadline {
                if d <= now {
                    continue;
                }
            }
            guard.insert(
                composite_key(&server, &tool, &args_hash),
                RememberedDecision {
                    decision: Decision::Allow,
                    deadline_secs: deadline,
                },
            );
        }
    }

    pub async fn forget_server(&self, server: &str) {
        let prefix = format!("{server}::");
        let mut guard = self.remembered.lock().await;
        guard.retain(|k, _| !k.starts_with(&prefix));
    }
}

#[derive(Debug, Clone)]
pub struct ApproveResult {
    pub server: String,
    pub tool: String,
    pub args_hash: String,
    pub persisted_deadline: Option<Option<i64>>,
}

fn composite_key(server: &str, tool: &str, args_hash: &str) -> String {
    format!("{server}::{tool}::{args_hash}")
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub async fn notify_user(server_name: &str, tool: &str, approval_id: &str) {
    let server = server_name.to_string();
    let tool = tool.to_string();
    let approval = approval_id.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        let msg = format!(
            "hatch approval required: server={server} tool={tool}\nApprove: hatch approve {approval}"
        );
        if cfg!(target_os = "macos") {
            let script = format!(
                "display notification \"{tool} from {server} ({approval})\" with title \"hatch approval\""
            );
            let _ = std::process::Command::new("osascript")
                .arg("-e")
                .arg(&script)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        } else {
            let _ = std::process::Command::new("notify-send")
                .arg("hatch approval")
                .arg(msg)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    })
    .await;
}
