#![deny(clippy::all)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unsupported schema version: {0}")]
    UnsupportedSchema(i64),
}

const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("../migrations/0001_init.sql"))];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRow {
    pub name: String,
    pub version: String,
    pub source: String,
    pub signature_verified: bool,
    pub risk_score: u32,
    pub installed_at: i64,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningServerRow {
    pub id: String,
    pub manifest_name: String,
    pub manifest_version: String,
    pub host: Option<String>,
    pub pid: Option<i64>,
    pub sandbox_backend: String,
    pub sandbox_id: String,
    pub started_at: i64,
    pub status: String,
}

pub struct Store {
    db_path: PathBuf,
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self, StateError> {
        let db_path = db_path.as_ref().to_path_buf();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(&db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let store = Store {
            db_path,
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.db_path
    }

    fn migrate(&self) -> Result<(), StateError> {
        let conn = self.conn.lock().expect("state mutex poisoned");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL
            );",
        )?;

        let current: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let now = now_seconds();
        for (v, sql) in MIGRATIONS {
            if *v <= current {
                continue;
            }
            conn.execute_batch(sql)?;
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                params![v, now],
            )?;
        }

        let max_known = MIGRATIONS.last().map(|m| m.0).unwrap_or(0);
        if current > max_known {
            return Err(StateError::UnsupportedSchema(current));
        }
        Ok(())
    }

    pub fn put_manifest(&self, row: &ManifestRow) -> Result<(), StateError> {
        let conn = self.conn.lock().expect("state mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO manifests
             (name, version, source, signature_verified, risk_score,
              installed_at, content, compiled_cache)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
            params![
                row.name,
                row.version,
                row.source,
                row.signature_verified as i64,
                row.risk_score,
                row.installed_at,
                row.content,
            ],
        )?;
        Ok(())
    }

    pub fn get_manifest_latest(&self, name: &str) -> Result<Option<ManifestRow>, StateError> {
        let conn = self.conn.lock().expect("state mutex poisoned");
        conn.query_row(
            "SELECT name, version, source, signature_verified, risk_score,
                    installed_at, content
             FROM manifests
             WHERE name = ?1
             ORDER BY installed_at DESC
             LIMIT 1",
            params![name],
            row_to_manifest,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn list_manifests(&self) -> Result<Vec<ManifestRow>, StateError> {
        let conn = self.conn.lock().expect("state mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT name, version, source, signature_verified, risk_score,
                    installed_at, content
             FROM manifests
             ORDER BY installed_at DESC",
        )?;
        let rows = stmt.query_map([], row_to_manifest)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn delete_manifest(&self, name: &str) -> Result<usize, StateError> {
        let conn = self.conn.lock().expect("state mutex poisoned");
        let n = conn.execute("DELETE FROM manifests WHERE name = ?1", params![name])?;
        Ok(n)
    }

    pub fn put_running(&self, row: &RunningServerRow) -> Result<(), StateError> {
        let conn = self.conn.lock().expect("state mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO running_servers
             (id, manifest_name, manifest_version, host, pid, sandbox_backend,
              sandbox_id, started_at, status)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                row.id,
                row.manifest_name,
                row.manifest_version,
                row.host,
                row.pid,
                row.sandbox_backend,
                row.sandbox_id,
                row.started_at,
                row.status,
            ],
        )?;
        Ok(())
    }

    pub fn set_status(&self, id: &str, status: &str) -> Result<(), StateError> {
        let conn = self.conn.lock().expect("state mutex poisoned");
        conn.execute(
            "UPDATE running_servers SET status = ?1 WHERE id = ?2",
            params![status, id],
        )?;
        Ok(())
    }

    pub fn get_running(&self, id: &str) -> Result<Option<RunningServerRow>, StateError> {
        let conn = self.conn.lock().expect("state mutex poisoned");
        conn.query_row(
            "SELECT id, manifest_name, manifest_version, host, pid,
                    sandbox_backend, sandbox_id, started_at, status
             FROM running_servers WHERE id = ?1",
            params![id],
            row_to_running,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn list_running(
        &self,
        include_finished: bool,
    ) -> Result<Vec<RunningServerRow>, StateError> {
        let conn = self.conn.lock().expect("state mutex poisoned");
        let sql = if include_finished {
            "SELECT id, manifest_name, manifest_version, host, pid,
                    sandbox_backend, sandbox_id, started_at, status
             FROM running_servers
             ORDER BY started_at DESC"
        } else {
            "SELECT id, manifest_name, manifest_version, host, pid,
                    sandbox_backend, sandbox_id, started_at, status
             FROM running_servers
             WHERE status IN ('starting','running','exiting')
             ORDER BY started_at DESC"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], row_to_running)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn delete_running(&self, id: &str) -> Result<(), StateError> {
        let conn = self.conn.lock().expect("state mutex poisoned");
        conn.execute("DELETE FROM running_servers WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn mark_orphans_crashed(&self) -> Result<usize, StateError> {
        let conn = self.conn.lock().expect("state mutex poisoned");
        let n = conn.execute(
            "UPDATE running_servers
             SET status = 'crashed'
             WHERE status IN ('starting','running','exiting')",
            [],
        )?;
        Ok(n)
    }

    pub fn get_config(&self, key: &str) -> Result<Option<String>, StateError> {
        let conn = self.conn.lock().expect("state mutex poisoned");
        conn.query_row(
            "SELECT value FROM daemon_config WHERE key = ?1",
            params![key],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn put_config(&self, key: &str, value: &str) -> Result<(), StateError> {
        let conn = self.conn.lock().expect("state mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO daemon_config (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }
}

fn row_to_manifest(r: &rusqlite::Row<'_>) -> rusqlite::Result<ManifestRow> {
    Ok(ManifestRow {
        name: r.get(0)?,
        version: r.get(1)?,
        source: r.get(2)?,
        signature_verified: r.get::<_, i64>(3)? != 0,
        risk_score: r.get::<_, i64>(4)? as u32,
        installed_at: r.get(5)?,
        content: r.get(6)?,
    })
}

fn row_to_running(r: &rusqlite::Row<'_>) -> rusqlite::Result<RunningServerRow> {
    Ok(RunningServerRow {
        id: r.get(0)?,
        manifest_name: r.get(1)?,
        manifest_version: r.get(2)?,
        host: r.get(3)?,
        pid: r.get(4)?,
        sandbox_backend: r.get(5)?,
        sandbox_id: r.get(6)?,
        started_at: r.get(7)?,
        status: r.get(8)?,
    })
}

fn now_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn store() -> (Store, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let s = Store::open(dir.path().join("state.db")).unwrap();
        (s, dir)
    }

    #[test]
    fn migrations_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.db");
        let _ = Store::open(&path).unwrap();
        let _ = Store::open(&path).unwrap();
    }

    #[test]
    fn put_get_list_manifest() {
        let (s, _d) = store();
        let m = ManifestRow {
            name: "github".into(),
            version: "1.0.0".into(),
            source: "local".into(),
            signature_verified: false,
            risk_score: 42,
            installed_at: 1_700_000_000,
            content: "schema_version = \"1.0\"".into(),
        };
        s.put_manifest(&m).unwrap();

        let got = s.get_manifest_latest("github").unwrap().unwrap();
        assert_eq!(got.version, "1.0.0");
        assert_eq!(got.risk_score, 42);

        let all = s.list_manifests().unwrap();
        assert_eq!(all.len(), 1);

        let removed = s.delete_manifest("github").unwrap();
        assert_eq!(removed, 1);
        assert!(s.get_manifest_latest("github").unwrap().is_none());
    }

    #[test]
    fn running_server_lifecycle() {
        let (s, _d) = store();
        s.put_manifest(&ManifestRow {
            name: "fs".into(),
            version: "0.1.0".into(),
            source: "local".into(),
            signature_verified: false,
            risk_score: 0,
            installed_at: 1,
            content: "".into(),
        })
        .unwrap();

        let r = RunningServerRow {
            id: "id-1".into(),
            manifest_name: "fs".into(),
            manifest_version: "0.1.0".into(),
            host: Some("cli".into()),
            pid: Some(12345),
            sandbox_backend: "stub".into(),
            sandbox_id: "stub-1".into(),
            started_at: 1_700_000_001,
            status: "running".into(),
        };
        s.put_running(&r).unwrap();
        s.set_status("id-1", "exited").unwrap();

        assert_eq!(s.list_running(false).unwrap().len(), 0);
        assert_eq!(s.list_running(true).unwrap().len(), 1);

        s.delete_running("id-1").unwrap();
        assert_eq!(s.list_running(true).unwrap().len(), 0);
    }

    #[test]
    fn config_round_trip() {
        let (s, _d) = store();
        assert!(s.get_config("k").unwrap().is_none());
        s.put_config("k", "v").unwrap();
        assert_eq!(s.get_config("k").unwrap().as_deref(), Some("v"));
    }

    #[test]
    fn orphan_crash_recovery() {
        let (s, _d) = store();
        s.put_manifest(&ManifestRow {
            name: "fs".into(),
            version: "0.1.0".into(),
            source: "local".into(),
            signature_verified: false,
            risk_score: 0,
            installed_at: 1,
            content: "".into(),
        })
        .unwrap();
        s.put_running(&RunningServerRow {
            id: "id-1".into(),
            manifest_name: "fs".into(),
            manifest_version: "0.1.0".into(),
            host: None,
            pid: None,
            sandbox_backend: "stub".into(),
            sandbox_id: "stub-1".into(),
            started_at: 1,
            status: "running".into(),
        })
        .unwrap();
        let crashed = s.mark_orphans_crashed().unwrap();
        assert_eq!(crashed, 1);
        let r = s.get_running("id-1").unwrap().unwrap();
        assert_eq!(r.status, "crashed");
    }
}
