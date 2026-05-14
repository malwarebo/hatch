use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hatch_ipc::RememberMode;
use tokio::sync::{oneshot, Mutex};
use uuid::Uuid;

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

type RememberedMap = HashMap<String, (Decision, Option<Instant>)>;

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
        let key = format!("{server_name}::{tool}::{args_hash}");
        let mut guard = self.remembered.lock().await;
        if let Some((dec, until)) = guard.get(&key).cloned() {
            if let Some(deadline) = until {
                if deadline <= Instant::now() {
                    guard.remove(&key);
                    return None;
                }
            }
            return Some(dec);
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

    pub async fn approve(
        &self,
        id: &str,
        remember: RememberMode,
    ) -> Option<(String, String, String)> {
        let pending = self.inner.lock().await.remove(id)?;
        let key = (
            pending.server_name.clone(),
            pending.tool.clone(),
            pending.args_hash.clone(),
        );
        let composite = format!("{}::{}::{}", key.0, key.1, key.2);
        match remember {
            RememberMode::Once => {}
            RememberMode::Session => {
                self.remembered
                    .lock()
                    .await
                    .insert(composite, (Decision::Allow, None));
            }
            RememberMode::ManifestVersion => {
                let deadline = Instant::now() + Duration::from_secs(60 * 60 * 24 * 30);
                self.remembered
                    .lock()
                    .await
                    .insert(composite, (Decision::Allow, Some(deadline)));
            }
        }
        let _ = pending.sender.send(Decision::Allow);
        Some(key)
    }

    pub async fn deny(&self, id: &str) -> Option<(String, String, String)> {
        let pending = self.inner.lock().await.remove(id)?;
        let key = (
            pending.server_name.clone(),
            pending.tool.clone(),
            pending.args_hash.clone(),
        );
        let _ = pending.sender.send(Decision::Deny);
        Some(key)
    }

    pub async fn timeout(&self, id: &str) {
        if let Some(pending) = self.inner.lock().await.remove(id) {
            let _ = pending.sender.send(Decision::Timeout);
        }
    }
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
