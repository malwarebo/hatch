#![deny(clippy::all)]

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

const FILE_DATE_FMT: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[year]-[month]-[day]");

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("time format: {0}")]
    Time(#[from] time::error::Format),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    DaemonStart,
    DaemonStop,
    ServerSpawn,
    ServerExit,
    ToolCall,
    ToolResponse,
    FsDenied,
    NetAttempt,
    NetDenied,
    PolicyViolation,
    ApprovalRequested,
    ApprovalGranted,
    ApprovalDenied,
    SignatureVerified,
    SignatureFailed,
    ConfigSync,
}

impl EventType {
    pub fn as_str(self) -> &'static str {
        match self {
            EventType::DaemonStart => "daemon_start",
            EventType::DaemonStop => "daemon_stop",
            EventType::ServerSpawn => "server_spawn",
            EventType::ServerExit => "server_exit",
            EventType::ToolCall => "tool_call",
            EventType::ToolResponse => "tool_response",
            EventType::FsDenied => "fs_denied",
            EventType::NetAttempt => "net_attempt",
            EventType::NetDenied => "net_denied",
            EventType::PolicyViolation => "policy_violation",
            EventType::ApprovalRequested => "approval_requested",
            EventType::ApprovalGranted => "approval_granted",
            EventType::ApprovalDenied => "approval_denied",
            EventType::SignatureVerified => "signature_verified",
            EventType::SignatureFailed => "signature_failed",
            EventType::ConfigSync => "config_sync",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: String,
    pub event_id: String,
    pub server: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub event: String,
    pub fields: BTreeMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
}

pub struct EventBuilder {
    server: String,
    server_id: Option<String>,
    host: Option<String>,
    event_type: EventType,
    fields: BTreeMap<String, serde_json::Value>,
}

impl EventBuilder {
    pub fn new(event_type: EventType) -> Self {
        Self {
            server: String::new(),
            server_id: None,
            host: None,
            event_type,
            fields: BTreeMap::new(),
        }
    }

    pub fn server(mut self, name: impl Into<String>) -> Self {
        self.server = name.into();
        self
    }

    pub fn server_id(mut self, id: impl Into<String>) -> Self {
        self.server_id = Some(id.into());
        self
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    pub fn field(mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

pub struct AuditWriter {
    inner: Mutex<Inner>,
    base_dir: PathBuf,
    hash_chain: bool,
}

struct Inner {
    current_date: String,
    file: BufWriter<File>,
    last_hash: Option<String>,
}

impl AuditWriter {
    pub fn open(base_dir: impl AsRef<Path>, hash_chain: bool) -> Result<Self, AuditError> {
        let base_dir = base_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&base_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&base_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let now = OffsetDateTime::now_utc();
        let current_date = now.format(FILE_DATE_FMT)?;
        let file = Self::open_today(&base_dir, &current_date)?;

        Ok(Self {
            inner: Mutex::new(Inner {
                current_date,
                file,
                last_hash: None,
            }),
            base_dir,
            hash_chain,
        })
    }

    fn open_today(base_dir: &Path, date: &str) -> Result<BufWriter<File>, AuditError> {
        let path = base_dir.join(format!("audit-{date}.jsonl"));
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;
        Ok(BufWriter::new(file))
    }

    pub fn seal_old_files(&self) -> Result<(), AuditError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let inner = self.inner.lock().expect("audit mutex poisoned");
            let today = format!("audit-{}.jsonl", inner.current_date);
            for entry in std::fs::read_dir(&self.base_dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with("audit-") || !name.ends_with(".jsonl") {
                    continue;
                }
                if name == today {
                    continue;
                }
                let perms = std::fs::Permissions::from_mode(0o400);
                let _ = std::fs::set_permissions(entry.path(), perms);
            }
        }
        Ok(())
    }

    pub fn write(&self, builder: EventBuilder) -> Result<AuditEvent, AuditError> {
        let event = self.build_event(builder)?;
        let mut line = serde_json::to_vec(&event)?;
        line.push(b'\n');

        let mut inner = self.inner.lock().expect("audit mutex poisoned");
        self.maybe_rotate(&mut inner)?;
        inner.file.write_all(&line)?;
        inner.file.flush()?;

        if self.hash_chain {
            let trimmed = &line[..line.len() - 1];
            let mut h = Sha256::new();
            h.update(trimmed);
            let digest = h.finalize();
            inner.last_hash = Some(base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest));
        }

        Ok(event)
    }

    fn build_event(&self, builder: EventBuilder) -> Result<AuditEvent, AuditError> {
        let now = OffsetDateTime::now_utc();
        let ts = now.format(&time::format_description::well_known::Rfc3339)?;
        let event_id = uuid::Uuid::new_v4().to_string();

        let prev_hash = if self.hash_chain {
            let inner = self.inner.lock().expect("audit mutex poisoned");
            inner.last_hash.clone()
        } else {
            None
        };

        Ok(AuditEvent {
            ts,
            event_id,
            server: builder.server,
            server_id: builder.server_id,
            host: builder.host,
            event: builder.event_type.as_str().to_string(),
            fields: builder.fields,
            prev_hash,
        })
    }

    fn maybe_rotate(&self, inner: &mut Inner) -> Result<(), AuditError> {
        let now = OffsetDateTime::now_utc();
        let today = now.format(FILE_DATE_FMT)?;
        if today == inner.current_date {
            return Ok(());
        }

        inner.file.flush()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let old_path = self
                .base_dir
                .join(format!("audit-{}.jsonl", inner.current_date));
            let perms = std::fs::Permissions::from_mode(0o400);
            let _ = std::fs::set_permissions(old_path, perms);
        }

        inner.file = Self::open_today(&self.base_dir, &today)?;
        inner.current_date = today;
        inner.last_hash = None;
        Ok(())
    }
}

pub mod args {
    use serde_json::{json, Value};

    pub const MAX_VALUE_LEN: usize = 64;

    pub fn summarize(args: &Value) -> Value {
        match args {
            Value::String(s) if s.len() > MAX_VALUE_LEN => {
                json!(format!("[redacted-{}-chars]", s.chars().count()))
            }
            Value::Object(map) => {
                let mut out = serde_json::Map::with_capacity(map.len());
                for (k, v) in map {
                    out.insert(k.clone(), summarize(v));
                }
                Value::Object(out)
            }
            Value::Array(items) => json!(format!("[{}-items]", items.len())),
            other => other.clone(),
        }
    }

    pub fn hash(args: &Value) -> String {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        let canon = serde_json::to_vec(args).unwrap_or_default();
        h.update(&canon);
        let digest = h.finalize();
        format!(
            "sha256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
        )
    }
}

pub fn read_file(path: impl AsRef<Path>) -> Result<(Vec<AuditEvent>, usize), AuditError> {
    let raw = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    let mut bad = 0;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEvent>(line) {
            Ok(ev) => out.push(ev),
            Err(_) => bad += 1,
        }
    }
    Ok((out, bad))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn round_trip_one_event() {
        let dir = tempdir().unwrap();
        let w = AuditWriter::open(dir.path(), true).unwrap();

        let ev = w
            .write(
                EventBuilder::new(EventType::ServerSpawn)
                    .server("filesystem")
                    .server_id("01H...")
                    .host("claude-desktop")
                    .field("manifest_version", "1.0.0")
                    .field("sandbox_backend", "stub"),
            )
            .unwrap();

        assert_eq!(ev.event, "server_spawn");
        assert_eq!(ev.server, "filesystem");
        assert_eq!(ev.fields.get("sandbox_backend").unwrap(), "stub");

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1);
        let (events, bad) = read_file(&files[0]).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(bad, 0);
    }

    #[test]
    fn hash_chain_links_events() {
        let dir = tempdir().unwrap();
        let w = AuditWriter::open(dir.path(), true).unwrap();
        let a = w
            .write(EventBuilder::new(EventType::DaemonStart).field("version", "0.1.0"))
            .unwrap();
        let b = w
            .write(EventBuilder::new(EventType::DaemonStop).field("reason", "test"))
            .unwrap();

        assert!(a.prev_hash.is_none());
        let prev = b.prev_hash.expect("second event has a prev_hash");
        let mut h = Sha256::new();
        h.update(serde_json::to_vec(&a).unwrap());
        let expected = base64::engine::general_purpose::STANDARD_NO_PAD.encode(h.finalize());
        assert_eq!(prev, expected);
    }

    #[test]
    fn args_summarisation_redacts_long_strings() {
        let big = "x".repeat(200);
        let v = json!({"repo": "r", "title": big, "rows": [1, 2, 3, 4]});
        let s = args::summarize(&v);
        let obj = s.as_object().unwrap();
        assert_eq!(obj.get("repo").unwrap(), "r");
        let t = obj.get("title").unwrap().as_str().unwrap();
        assert!(t.starts_with("[redacted-"));
        assert!(obj
            .get("rows")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("4-items"));
    }

    #[test]
    fn read_file_skips_corruption() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-2026-05-13.jsonl");
        std::fs::write(
            &path,
            "{\"ts\":\"2026-05-13T00:00:00Z\",\"event_id\":\"id\",\"server\":\"x\",\
             \"event\":\"daemon_start\",\"fields\":{}}\n\
             not-json\n",
        )
        .unwrap();
        let (events, bad) = read_file(&path).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(bad, 1);
    }
}
