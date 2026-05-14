use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DaemonPaths {
    pub state_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub audit_dir: PathBuf,
    pub db_path: PathBuf,
    pub socket_path: PathBuf,
    pub log_dir: PathBuf,
}

impl DaemonPaths {
    pub fn default_for_user() -> Self {
        if let Ok(custom) = std::env::var("HATCH_STATE_DIR") {
            let base = PathBuf::from(custom);
            return Self::from_state_root(&base);
        }
        platform_default()
    }

    pub fn from_state_root(state_dir: &Path) -> Self {
        let runtime_dir = state_dir.join("runtime");
        let audit_dir = state_dir.join("audit");
        let log_dir = state_dir.join("logs");
        let db_path = state_dir.join("state.db");
        let socket_path = runtime_dir.join("daemon.sock");
        Self {
            state_dir: state_dir.to_path_buf(),
            runtime_dir,
            audit_dir,
            log_dir,
            db_path,
            socket_path,
        }
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        for d in [
            &self.state_dir,
            &self.runtime_dir,
            &self.audit_dir,
            &self.log_dir,
        ] {
            std::fs::create_dir_all(d)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn platform_default() -> DaemonPaths {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let state = home.join("Library/Application Support/hatch/state");
    let runtime = std::env::var("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
        .join("hatch");
    let log = home.join("Library/Logs/hatch");
    let audit = state.join("audit");
    let db = state.join("state.db");
    let socket = runtime.join("daemon.sock");
    DaemonPaths {
        state_dir: state,
        runtime_dir: runtime,
        audit_dir: audit,
        log_dir: log,
        db_path: db,
        socket_path: socket,
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_default() -> DaemonPaths {
    let state = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| PathBuf::from(".local/state"))
        .join("hatch");
    let runtime = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| state.clone())
        .join("hatch");
    let audit = state.join("audit");
    let log = state.join("logs");
    let db = state.join("state.db");
    let socket = runtime.join("daemon.sock");
    DaemonPaths {
        state_dir: state,
        runtime_dir: runtime,
        audit_dir: audit,
        log_dir: log,
        db_path: db,
        socket_path: socket,
    }
}

#[cfg(not(unix))]
fn platform_default() -> DaemonPaths {
    let base = PathBuf::from(".hatch-state");
    DaemonPaths::from_state_root(&base)
}
