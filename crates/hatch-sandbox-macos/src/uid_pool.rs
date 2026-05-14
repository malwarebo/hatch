use std::process::Command;
use std::sync::Mutex;

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
