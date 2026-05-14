use std::io::Write;
use std::process::Command;

use anyhow::{anyhow, Result};

pub fn generate_anchor(
    user: &str,
    proxy_addr: &str,
    proxy_port: u16,
    dns_addr: &str,
    dns_port: u16,
) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "table <hatch_proxy_{user}> persist {{ {proxy_addr} }}\n"
    ));
    s.push_str(&format!(
        "table <hatch_dns_{user}> persist {{ {dns_addr} }}\n"
    ));
    s.push_str(&format!(
        "pass out quick proto tcp from any to <hatch_proxy_{user}> port {proxy_port} user {user} keep state\n"
    ));
    s.push_str(&format!(
        "pass out quick proto udp from any to <hatch_dns_{user}> port {dns_port} user {user} keep state\n"
    ));
    s.push_str(&format!("block drop out quick from any user {user}\n"));
    s
}

pub fn load_anchor(server_id: &str, rules: &str) -> Result<()> {
    let anchor = format!("hatch/{server_id}");
    let mut child = Command::new("pfctl")
        .arg("-a")
        .arg(&anchor)
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow!("spawn pfctl: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(rules.as_bytes())
            .map_err(|e| anyhow!("write pfctl stdin: {e}"))?;
    }
    let status = child.wait().map_err(|e| anyhow!("wait pfctl: {e}"))?;
    if !status.success() {
        return Err(anyhow!("pfctl exited {:?}", status.code()));
    }
    Ok(())
}

pub fn unload_anchor(server_id: &str) {
    let anchor = format!("hatch/{server_id}");
    let _ = Command::new("pfctl")
        .arg("-a")
        .arg(&anchor)
        .arg("-F")
        .arg("all")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_text_well_formed() {
        let s = generate_anchor("_hatch_001", "127.0.0.1", 8443, "127.0.0.1", 1053);
        assert!(s.contains("table <hatch_proxy__hatch_001>"));
        assert!(s.contains("pass out quick proto tcp"));
        assert!(s.contains("block drop out quick"));
    }
}
