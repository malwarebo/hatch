use std::process::Command;
use std::sync::Mutex;

use anyhow::{anyhow, Result};

pub struct UidPool {
    available: Mutex<Vec<String>>,
}

impl UidPool {
    pub fn discover() -> Self {
        let mut available = Vec::new();
        for i in 1..=64u32 {
            let user = format!("_hatch_{i:03}");
            if user_exists(&user) {
                available.push(user);
            }
        }
        Self {
            available: Mutex::new(available),
        }
    }

    pub fn checkout(&self) -> Option<String> {
        self.available.lock().ok()?.pop()
    }

    pub fn return_uid(&self, user: String) {
        if let Ok(mut a) = self.available.lock() {
            a.push(user);
        }
    }

    pub fn size(&self) -> usize {
        self.available.lock().map(|a| a.len()).unwrap_or(0)
    }
}

fn user_exists(user: &str) -> bool {
    Command::new("dscl")
        .arg(".")
        .arg("-read")
        .arg(format!("/Users/{user}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn install_pool() -> Result<()> {
    let script = crate::profile::render_uid_installer();
    let dir = std::env::temp_dir();
    let path = dir.join("hatch-install-uids.sh");
    std::fs::write(&path, script).map_err(|e| anyhow!("write installer: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
    }
    let status = Command::new("bash")
        .arg(&path)
        .status()
        .map_err(|e| anyhow!("run installer: {e}"))?;
    if !status.success() {
        return Err(anyhow!("installer exited {:?}", status.code()));
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}
