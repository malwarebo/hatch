use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;

pub struct ObservationReport {
    pub paths_read: BTreeSet<String>,
    pub paths_written: BTreeSet<String>,
    pub network_hosts: BTreeSet<String>,
    pub subprocess_binaries: BTreeSet<String>,
}

impl ObservationReport {
    pub fn empty() -> Self {
        Self {
            paths_read: BTreeSet::new(),
            paths_written: BTreeSet::new(),
            network_hosts: BTreeSet::new(),
            subprocess_binaries: BTreeSet::new(),
        }
    }
}

pub async fn observe(program: &str, args: &[String], output: Option<PathBuf>) -> Result<()> {
    let report = if cfg!(target_os = "linux") {
        observe_with_strace(program, args).await?
    } else if cfg!(target_os = "macos") {
        observe_with_dtruss(program, args).await?
    } else {
        return Err(anyhow!(
            "observation mode is only supported on Linux and macOS"
        ));
    };

    let manifest = synthesize_manifest(program, args, &report);

    match output {
        Some(path) => {
            std::fs::write(&path, manifest).context("write manifest")?;
            eprintln!("hatch: candidate manifest written to {}", path.display());
        }
        None => {
            std::io::stdout().write_all(manifest.as_bytes()).ok();
        }
    }
    Ok(())
}

async fn observe_with_strace(program: &str, args: &[String]) -> Result<ObservationReport> {
    let mut cmd = Command::new("strace");
    cmd.arg("-f")
        .arg("-e")
        .arg("trace=openat,connect,execve,bind")
        .arg("-s")
        .arg("512")
        .arg("--")
        .arg(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    parse_strace(cmd).await
}

async fn observe_with_dtruss(program: &str, args: &[String]) -> Result<ObservationReport> {
    let mut cmd = Command::new("dtruss");
    cmd.arg("-f")
        .arg("-t")
        .arg("openat,connect,execve")
        .arg("--")
        .arg(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    parse_strace(cmd).await
}

async fn parse_strace(mut cmd: Command) -> Result<ObservationReport> {
    let mut report = ObservationReport::empty();
    let mut child = cmd
        .spawn()
        .context("spawn tracer; is strace/dtruss installed?")?;

    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("missing stderr handle"))?;
    let mut reader = tokio::io::BufReader::new(stderr).lines();

    let open_re = Regex::new(r#"openat\([^,]+,\s*"([^"]+)"[^)]*\)\s*=\s*(-?\d+)"#)?;
    let connect_re = Regex::new(r#"connect\(\d+,\s*\{[^}]*\}[^=]*=\s*(-?\d+)"#)?;
    let hostport_re = Regex::new(r#"sa_data="([^"]+)""#)?;
    let execve_re = Regex::new(r#"execve\("([^"]+)""#)?;

    while let Ok(Some(line)) = reader.next_line().await {
        if let Some(c) = open_re.captures(&line) {
            let path = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            let rc: i64 = c.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
            if rc < 0 || path.is_empty() {
                continue;
            }
            if line.contains("O_WRONLY") || line.contains("O_RDWR") || line.contains("O_CREAT") {
                report.paths_written.insert(normalize_path(&path));
            } else {
                report.paths_read.insert(normalize_path(&path));
            }
        }
        if connect_re.is_match(&line) {
            if let Some(h) = hostport_re.captures(&line) {
                if let Some(m) = h.get(1) {
                    report.network_hosts.insert(m.as_str().to_string());
                }
            }
        }
        if let Some(c) = execve_re.captures(&line) {
            if let Some(m) = c.get(1) {
                report.subprocess_binaries.insert(m.as_str().to_string());
            }
        }
    }

    let _ = child.wait().await;
    Ok(report)
}

fn normalize_path(p: &str) -> String {
    if let Some(idx) = p.find("/site-packages/") {
        return collapse_segment(p, idx, "/site-packages/");
    }
    if let Some(idx) = p.find("/node_modules/") {
        return collapse_segment(p, idx, "/node_modules/");
    }
    p.to_string()
}

fn collapse_segment(p: &str, idx: usize, marker: &str) -> String {
    let tail = &p[idx + marker.len()..];
    let first = tail.split('/').next().unwrap_or(tail).to_string();
    let mut out = p[..idx + marker.len()].to_string();
    out.push_str(&first);
    out
}

fn synthesize_manifest(program: &str, args: &[String], r: &ObservationReport) -> String {
    let mut out = String::new();
    out.push_str("schema_version = \"1.0\"\n");
    out.push_str("name = \"observed\"\n");
    out.push_str("version = \"0.1.0\"\n");
    out.push_str("description = \"Candidate manifest generated by `hatch observe`\"\n\n");

    out.push_str("[command]\n");
    out.push_str(&format!("program = {}\n", toml_string(program)));
    if args.is_empty() {
        out.push_str("args = []\n");
    } else {
        out.push_str("args = [");
        for (i, a) in args.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&toml_string(a));
        }
        out.push_str("]\n");
    }
    out.push('\n');

    out.push_str("[network]\n");
    out.push_str("# observed: hostnames extracted from connect() syscalls\n");
    out.push_str("allow_https = [");
    for (i, h) in r.network_hosts.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&toml_string(h));
    }
    out.push_str("]\nallow_dns = []\nallow_http = false\n\n");

    out.push_str("[filesystem]\n");
    out.push_str("# observed: readable paths\n");
    out.push_str("read = [");
    for (i, p) in r.paths_read.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&toml_string(p));
    }
    out.push_str("]\n");
    out.push_str("# observed: writable paths\n");
    out.push_str("write = [");
    for (i, p) in r.paths_written.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&toml_string(p));
    }
    out.push_str("]\ntmpfs = [\"/tmp\"]\n\n");

    out.push_str("[env]\npassthrough = []\n\n");

    out.push_str("[exec]\n");
    if r.subprocess_binaries.is_empty() {
        out.push_str("allow_subprocess = false\nallow_binaries = []\n");
    } else {
        out.push_str("allow_subprocess = true\n# observed: binaries invoked via execve\n");
        out.push_str("allow_binaries = [");
        for (i, b) in r.subprocess_binaries.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&toml_string(b));
        }
        out.push_str("]\n");
    }
    out.push('\n');

    out.push_str("[resources]\n");
    out.push_str("memory_mb = 256\ncpu_percent = 50\npids_max = 50\nnofile = 256\n");
    out.push_str("tool_call_timeout_seconds = 60\n\n");

    out.push_str("[tool_policy]\nrequire_approval = []\ndeny = []\n\n");
    out.push_str("[platform.linux]\nseccomp_preset = \"strict\"\nlandlock = true\n\n");
    out.push_str("[platform.macos]\nendpoint_security = false\n");
    out
}

fn toml_string(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}
