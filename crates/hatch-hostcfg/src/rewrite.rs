use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::hosts::{HostKind, HostSpec};

#[derive(Debug, Error)]
pub enum RewriteError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("config has no {field:?} object")]
    NoMcpServers { field: String },
    #[error("config is already wrapped; pass force=true to overwrite")]
    AlreadyWrapped,
    #[error("backup mismatch when restoring {path:?}; restore manually from .hatch-backup-*")]
    BackupMismatch { path: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRecord {
    pub command: Option<Value>,
    pub args: Option<Value>,
    pub env: Option<Value>,
    pub url: Option<Value>,
    pub other: Value,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct RewriteReport {
    pub host: String,
    pub wrapped_servers: Vec<String>,
    pub skipped: bool,
    pub backup_path: Option<PathBuf>,
}

#[derive(Debug, Default, Clone)]
pub struct RewriteOptions {
    pub shim_path: String,
    pub force: bool,
    pub state_dir: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct HostStatus {
    pub host: String,
    pub path: PathBuf,
    pub exists: bool,
    pub wrapped: bool,
    pub mcp_server_count: usize,
}

pub fn sync(spec: &HostSpec, opts: &RewriteOptions) -> Result<RewriteReport, RewriteError> {
    if !spec.path.exists() {
        return Ok(RewriteReport {
            host: spec.kind.slug().into(),
            wrapped_servers: vec![],
            skipped: true,
            backup_path: None,
        });
    }
    let raw = std::fs::read_to_string(&spec.path)?;
    let mut doc: Value = serde_json::from_str(&raw)?;

    if doc.get("_hatch").is_some() && !opts.force {
        return Err(RewriteError::AlreadyWrapped);
    }

    let backup_path = backup_file(&spec.path)?;
    std::fs::write(&backup_path, &raw)?;

    let field = spec.kind.config_field();
    let mut wrapped_servers = Vec::new();
    let mut originals = serde_json::Map::new();

    let target = match spec.kind {
        HostKind::Zed => doc.get_mut(field),
        _ => doc.get_mut(field),
    };

    if let Some(Value::Object(servers)) = target {
        for (name, entry) in servers.iter_mut() {
            let original = entry.clone();
            originals.insert(name.clone(), original.clone());
            let mut shim_env = serde_json::Map::new();
            shim_env.insert("HATCH_SERVER".into(), Value::String(name.clone()));
            shim_env.insert("HATCH_HOST".into(), Value::String(spec.kind.slug().into()));
            if let Some(state_dir) = opts.state_dir.as_ref() {
                shim_env.insert("HATCH_STATE_DIR".into(), Value::String(state_dir.clone()));
            }
            *entry = json!({
                "command": opts.shim_path,
                "args": [],
                "env": Value::Object(shim_env),
            });
            wrapped_servers.push(name.clone());
        }
    } else {
        return Err(RewriteError::NoMcpServers {
            field: field.into(),
        });
    }

    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    doc["_hatch"] = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "wrapped_at": now,
        "original_servers": Value::Object(originals),
    });

    write_pretty(&spec.path, &doc)?;
    Ok(RewriteReport {
        host: spec.kind.slug().into(),
        wrapped_servers,
        skipped: false,
        backup_path: Some(backup_path),
    })
}

pub fn restore(spec: &HostSpec) -> Result<RewriteReport, RewriteError> {
    if !spec.path.exists() {
        return Ok(RewriteReport {
            host: spec.kind.slug().into(),
            wrapped_servers: vec![],
            skipped: true,
            backup_path: None,
        });
    }
    let raw = std::fs::read_to_string(&spec.path)?;
    let mut doc: Value = serde_json::from_str(&raw)?;

    let Some(meta) = doc.get("_hatch").cloned() else {
        return Ok(RewriteReport {
            host: spec.kind.slug().into(),
            wrapped_servers: vec![],
            skipped: true,
            backup_path: None,
        });
    };

    let originals = meta
        .get("original_servers")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    let field = spec.kind.config_field();
    if let Some(Value::Object(servers)) = doc.get_mut(field) {
        for (name, original) in &originals {
            servers.insert(name.clone(), original.clone());
        }
        servers.retain(|name, _| originals.contains_key(name));
    }

    if let Some(obj) = doc.as_object_mut() {
        obj.remove("_hatch");
    }

    let latest_backup = latest_backup_file(&spec.path)?;
    if let Some(bpath) = latest_backup.as_ref() {
        let original_bytes = std::fs::read_to_string(bpath)?;
        let new_doc = serde_json::to_string_pretty(&doc)?;
        let original_norm = normalize_json(&original_bytes)?;
        let new_norm = normalize_json(&new_doc)?;
        if original_norm != new_norm {
            return Err(RewriteError::BackupMismatch {
                path: spec.path.clone(),
            });
        }
    }
    write_pretty(&spec.path, &doc)?;

    let restored: Vec<String> = originals.keys().cloned().collect();
    Ok(RewriteReport {
        host: spec.kind.slug().into(),
        wrapped_servers: restored,
        skipped: false,
        backup_path: latest_backup,
    })
}

pub fn status(spec: &HostSpec) -> HostStatus {
    let mut s = HostStatus {
        host: spec.kind.slug().into(),
        path: spec.path.clone(),
        exists: spec.path.exists(),
        wrapped: false,
        mcp_server_count: 0,
    };
    if !s.exists {
        return s;
    }
    if let Ok(raw) = std::fs::read_to_string(&spec.path) {
        if let Ok(doc) = serde_json::from_str::<Value>(&raw) {
            s.wrapped = doc.get("_hatch").is_some();
            if let Some(Value::Object(m)) = doc.get(spec.kind.config_field()) {
                s.mcp_server_count = m.len();
            }
        }
    }
    s
}

fn write_pretty(path: &Path, doc: &Value) -> std::io::Result<()> {
    let mut s = serde_json::to_string_pretty(doc).unwrap_or_default();
    s.push('\n');
    std::fs::write(path, s)
}

fn backup_file(path: &Path) -> std::io::Result<PathBuf> {
    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "now".into())
        .replace(':', "-");
    let mut name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config".into());
    name.push_str(".hatch-backup-");
    name.push_str(&ts);
    let mut out = path.to_path_buf();
    out.set_file_name(name);
    Ok(out)
}

fn latest_backup_file(path: &Path) -> std::io::Result<Option<PathBuf>> {
    let parent = match path.parent() {
        Some(p) => p,
        None => return Ok(None),
    };
    let base = match path.file_name() {
        Some(s) => s.to_string_lossy().into_owned(),
        None => return Ok(None),
    };
    let prefix = format!("{base}.hatch-backup-");

    let mut candidates = Vec::new();
    if !parent.exists() {
        return Ok(None);
    }
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let n = entry.file_name();
        let n = n.to_string_lossy();
        if n.starts_with(&prefix) {
            candidates.push(entry.path());
        }
    }
    candidates.sort();
    Ok(candidates.into_iter().last())
}

fn normalize_json(s: &str) -> Result<Value, RewriteError> {
    let v: Value = serde_json::from_str(s)?;
    let mut v = strip_hatch_field(v);
    canonicalize(&mut v);
    Ok(v)
}

fn strip_hatch_field(mut v: Value) -> Value {
    if let Value::Object(ref mut obj) = v {
        obj.remove("_hatch");
    }
    v
}

fn canonicalize(v: &mut Value) {
    if let Value::Object(obj) = v {
        let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
        for (k, mut inner) in std::mem::take(obj) {
            canonicalize(&mut inner);
            sorted.insert(k, inner);
        }
        let m: serde_json::Map<String, Value> = sorted.into_iter().collect();
        *obj = m;
    } else if let Value::Array(arr) = v {
        for item in arr.iter_mut() {
            canonicalize(item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_claude_config(dir: &Path) -> PathBuf {
        let path = dir.join("claude_desktop_config.json");
        std::fs::write(
            &path,
            r#"{
  "mcpServers": {
    "github": { "command": "npx", "args": ["-y", "pkg"], "env": {"GITHUB_TOKEN": "tok"} },
    "filesystem": { "command": "node", "args": ["fs.js"] }
  }
}
"#,
        )
        .unwrap();
        path
    }

    #[test]
    fn sync_wraps_claude_desktop() {
        let dir = tempdir().unwrap();
        let path = write_claude_config(dir.path());
        let spec = HostSpec {
            kind: HostKind::ClaudeDesktop,
            path: path.clone(),
        };
        let opts = RewriteOptions {
            shim_path: "/usr/local/bin/hatch-shim".into(),
            force: false,
            state_dir: Some("/tmp/state".into()),
        };
        let report = sync(&spec, &opts).unwrap();
        assert_eq!(report.wrapped_servers.len(), 2);
        assert!(!report.skipped);

        let raw = std::fs::read_to_string(&path).unwrap();
        let doc: Value = serde_json::from_str(&raw).unwrap();
        assert!(doc.get("_hatch").is_some());
        assert_eq!(
            doc["mcpServers"]["github"]["command"],
            "/usr/local/bin/hatch-shim"
        );
        assert_eq!(doc["mcpServers"]["github"]["env"]["HATCH_SERVER"], "github");
    }

    #[test]
    fn restore_returns_to_original() {
        let dir = tempdir().unwrap();
        let path = write_claude_config(dir.path());
        let original = std::fs::read_to_string(&path).unwrap();
        let spec = HostSpec {
            kind: HostKind::ClaudeDesktop,
            path: path.clone(),
        };
        let opts = RewriteOptions {
            shim_path: "/usr/local/bin/hatch-shim".into(),
            ..Default::default()
        };
        sync(&spec, &opts).unwrap();
        let report = restore(&spec).unwrap();
        assert_eq!(report.wrapped_servers.len(), 2);

        let restored = std::fs::read_to_string(&path).unwrap();
        let a: Value = serde_json::from_str(&original).unwrap();
        let b: Value = serde_json::from_str(&restored).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn already_wrapped_returns_error_without_force() {
        let dir = tempdir().unwrap();
        let path = write_claude_config(dir.path());
        let spec = HostSpec {
            kind: HostKind::ClaudeDesktop,
            path: path.clone(),
        };
        let opts = RewriteOptions {
            shim_path: "/usr/local/bin/hatch-shim".into(),
            ..Default::default()
        };
        sync(&spec, &opts).unwrap();
        let err = sync(&spec, &opts).unwrap_err();
        assert!(matches!(err, RewriteError::AlreadyWrapped));
    }

    #[test]
    fn status_reports_wrapped_count() {
        let dir = tempdir().unwrap();
        let path = write_claude_config(dir.path());
        let spec = HostSpec {
            kind: HostKind::ClaudeDesktop,
            path: path.clone(),
        };
        let opts = RewriteOptions {
            shim_path: "/usr/local/bin/hatch-shim".into(),
            ..Default::default()
        };
        let pre = status(&spec);
        assert!(pre.exists);
        assert!(!pre.wrapped);
        assert_eq!(pre.mcp_server_count, 2);
        sync(&spec, &opts).unwrap();
        let post = status(&spec);
        assert!(post.wrapped);
        assert_eq!(post.mcp_server_count, 2);
    }
}
