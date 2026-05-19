#![deny(clippy::all)]

mod observe;
mod tui;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hatch_core::{validate, Manifest};
use hatch_hostcfg::{
    restore as hostcfg_restore, status as hostcfg_status, sync as hostcfg_sync, HostKind, HostSpec,
    RewriteOptions,
};
use hatch_ipc::{
    AuditFilter, ClientRequest, Codec, DaemonPaths, DaemonResponse, ErrorCode, InstallSource,
    RememberMode,
};
use hatch_registry::Registry;
use tokio::net::UnixStream;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "hatch",
    version,
    about = "Capability-based isolation for AI tool servers"
)]
struct Cli {
    #[arg(long, env = "HATCH_SOCKET")]
    socket: Option<PathBuf>,

    #[arg(long, env = "HATCH_STATE_DIR")]
    state_dir: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    #[command(about = "Show daemon status")]
    Status,
    #[command(about = "Show hatch version")]
    Version,
    #[command(about = "Diagnose installation issues")]
    Doctor,
    #[command(about = "List installed manifests")]
    List {
        #[arg(long)]
        running: bool,
    },
    #[command(about = "List running sandboxed servers")]
    Ps,
    #[command(about = "Manually spawn an installed manifest (foreground)")]
    Run {
        name: String,
        #[arg(long, default_value_t = 5)]
        seconds: u64,
    },
    #[command(about = "Stop a running server (id or name)")]
    Stop { target: String },
    #[command(about = "Inspect a running sandboxed server")]
    Inspect { target: String },
    #[command(about = "Install a manifest")]
    Install {
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        allow_unsigned: bool,
        name: Option<String>,
    },
    #[command(about = "Uninstall a manifest")]
    Uninstall { name: String },
    #[command(about = "Approve a pending policy request")]
    Approve {
        approval_id: String,
        #[arg(long, value_enum, default_value_t = RememberFlag::Once)]
        remember: RememberFlag,
    },
    #[command(about = "Deny a pending policy request")]
    Deny { approval_id: String },
    #[command(about = "View audit events")]
    Audit {
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        event_type: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        since_seconds: Option<u64>,
        #[arg(long)]
        tui: bool,
        #[arg(long)]
        follow: bool,
    },
    #[command(about = "Run a program with syscall tracing and emit a candidate manifest")]
    Observe {
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(last = true)]
        command: Vec<String>,
    },
    #[command(subcommand, about = "Manifest tools")]
    Manifest(ManifestCmd),
    #[command(subcommand, about = "MCP host config rewriting")]
    Config(ConfigCmd),
    #[command(subcommand, about = "Registry tools", name = "registry")]
    Registry(RegistrySubCmd),
    #[command(subcommand, about = "Daemon control")]
    Daemon(DaemonCmd),
    #[command(subcommand, about = "Debug helpers")]
    Debug(DebugCmd),
}

#[derive(Debug, Subcommand)]
enum DebugCmd {
    #[command(about = "Verify the SHA-256 hash chain across an audit JSONL file")]
    AuditVerify {
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        all: bool,
    },
    #[command(about = "Render the compiled platform sandbox profile for an installed manifest")]
    Profile { name: String },
}

#[derive(Debug, Subcommand)]
enum ManifestCmd {
    Validate {
        path: PathBuf,
    },
    Explain {
        path: PathBuf,
    },
    Show {
        name: String,
    },
    Diff {
        name: String,
        path: PathBuf,
    },
    #[command(about = "Open an installed manifest in $EDITOR; validates and reinstalls on save")]
    Edit {
        name: String,
        #[arg(long, help = "Skip signature checks on reinstall")]
        allow_unsigned: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCmd {
    Status {
        #[arg(long, help = "Also check ./.cursor/mcp.json in the current directory")]
        workspace: bool,
    },
    Sync {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        shim_path: Option<String>,
        #[arg(long)]
        force: bool,
        #[arg(
            long,
            help = "Rewrite ./.cursor/mcp.json in the current directory instead of the global Cursor config"
        )]
        workspace: bool,
        #[arg(
            long,
            value_name = "PATH",
            help = "Rewrite the per-workspace .cursor/mcp.json under PATH"
        )]
        workspace_path: Option<PathBuf>,
    },
    Unsync {
        #[arg(long)]
        host: Option<String>,
        #[arg(long, help = "Restore ./.cursor/mcp.json in the current directory")]
        workspace: bool,
        #[arg(long, value_name = "PATH")]
        workspace_path: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum RegistrySubCmd {
    InstallBundle { path: PathBuf },
    List,
    Verify { name: String },
}

#[derive(Debug, Subcommand)]
enum DaemonCmd {
    Status,
    Stop,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum RememberFlag {
    Once,
    Session,
    ManifestVersion,
}

impl From<RememberFlag> for RememberMode {
    fn from(f: RememberFlag) -> Self {
        match f {
            RememberFlag::Once => RememberMode::Once,
            RememberFlag::Session => RememberMode::Session,
            RememberFlag::ManifestVersion => RememberMode::ManifestVersion,
        }
    }
}

fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("HATCH_LOG").unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();

    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hatch: tokio init: {e}");
            return ExitCode::from(1);
        }
    };
    match rt.block_on(run(cli)) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("hatch: {err:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> Result<u8> {
    let paths = match &cli.state_dir {
        Some(p) => DaemonPaths::from_state_root(p),
        None => DaemonPaths::default_for_user(),
    };
    let socket = cli
        .socket
        .clone()
        .unwrap_or_else(|| paths.socket_path.clone());

    match cli.command {
        Cmd::Version => {
            println!("hatch {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        Cmd::Doctor => cmd_doctor(&socket, &paths),

        Cmd::Manifest(ManifestCmd::Validate { path }) => cmd_manifest_validate(&path, cli.format),
        Cmd::Manifest(ManifestCmd::Explain { path }) => cmd_manifest_explain(&path, cli.format),
        Cmd::Manifest(ManifestCmd::Show { name }) => cmd_manifest_show(&socket, &name).await,
        Cmd::Manifest(ManifestCmd::Diff { name, path }) => {
            cmd_manifest_diff(&socket, &name, &path).await
        }
        Cmd::Manifest(ManifestCmd::Edit {
            name,
            allow_unsigned,
        }) => cmd_manifest_edit(&socket, &paths, &name, allow_unsigned).await,

        Cmd::Observe { output, command } => {
            if command.is_empty() {
                return Err(anyhow::anyhow!(
                    "usage: hatch observe -- <program> [args...]"
                ));
            }
            let (program, args) = (command[0].clone(), command[1..].to_vec());
            observe::observe(&program, &args, output).await?;
            Ok(0)
        }

        Cmd::Status | Cmd::Daemon(DaemonCmd::Status) => {
            let resp = call_one(&socket, ClientRequest::DaemonStatus).await?;
            print_status(&resp, cli.format)
        }
        Cmd::Daemon(DaemonCmd::Stop) => {
            let _ = call_one(&socket, ClientRequest::DaemonStop).await?;
            println!("daemon stop signal sent");
            Ok(0)
        }
        Cmd::List { running } => {
            if running {
                let resp = call_one(&socket, ClientRequest::ListRunning).await?;
                print_ps(&resp, cli.format)
            } else {
                let resp = call_one(&socket, ClientRequest::ListManifests).await?;
                print_list(&resp, cli.format)
            }
        }
        Cmd::Ps => {
            let resp = call_one(&socket, ClientRequest::ListRunning).await?;
            print_ps(&resp, cli.format)
        }
        Cmd::Stop { target } => {
            let resp = call_one(&socket, ClientRequest::Stop { target }).await?;
            expect_ok(&resp)
        }
        Cmd::Inspect { target } => {
            let resp = call_one(&socket, ClientRequest::Inspect { target }).await?;
            print_inspect(&resp, cli.format)
        }
        Cmd::Run { name, seconds } => cmd_run(&socket, &name, seconds).await,
        Cmd::Approve {
            approval_id,
            remember,
        } => {
            let resp = call_one(
                &socket,
                ClientRequest::Approve {
                    approval_id,
                    remember: remember.into(),
                },
            )
            .await?;
            expect_ok(&resp)
        }
        Cmd::Deny { approval_id } => {
            let resp = call_one(&socket, ClientRequest::Deny { approval_id }).await?;
            expect_ok(&resp)
        }
        Cmd::Audit {
            server,
            event_type,
            limit,
            since_seconds,
            tui: use_tui,
            follow: _,
        } => {
            if use_tui {
                tui::run_tui(socket, server).await?;
                Ok(0)
            } else {
                let resp = call_one(
                    &socket,
                    ClientRequest::Audit {
                        filter: AuditFilter {
                            server,
                            event_type,
                            since_seconds,
                            limit: Some(limit),
                        },
                        follow: false,
                    },
                )
                .await?;
                print_audit(&resp, cli.format)
            }
        }
        Cmd::Install {
            file,
            allow_unsigned,
            name,
        } => {
            let source = if let Some(path) = file {
                InstallSource::File {
                    path: path.to_string_lossy().into_owned(),
                }
            } else if let Some(name) = name {
                InstallSource::Registry {
                    name,
                    version: None,
                }
            } else {
                return Err(anyhow::anyhow!(
                    "either --file <path> or a manifest name is required"
                ));
            };
            let resp = call_one(
                &socket,
                ClientRequest::Install {
                    source,
                    allow_unsigned,
                },
            )
            .await?;
            expect_ok(&resp)
        }
        Cmd::Uninstall { name } => {
            let resp = call_one(&socket, ClientRequest::Uninstall { name }).await?;
            expect_ok(&resp)
        }

        Cmd::Config(c) => cmd_config(c, &paths),
        Cmd::Registry(c) => cmd_registry(c, &paths, cli.format),
        Cmd::Debug(c) => cmd_debug(c, &paths, cli.format).await,
    }
}

async fn cmd_debug(c: DebugCmd, paths: &DaemonPaths, format: OutputFormat) -> Result<u8> {
    match c {
        DebugCmd::AuditVerify { path, all } => {
            let mut files: Vec<PathBuf> = Vec::new();
            if let Some(p) = path {
                files.push(p);
            } else if all {
                if let Ok(entries) = std::fs::read_dir(&paths.audit_dir) {
                    for e in entries.flatten() {
                        let p = e.path();
                        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                            if name.starts_with("audit-") && name.ends_with(".jsonl") {
                                files.push(p);
                            }
                        }
                    }
                    files.sort();
                }
            } else {
                let today = time::OffsetDateTime::now_utc()
                    .format(&time::macros::format_description!("[year]-[month]-[day]"))
                    .unwrap_or_default();
                files.push(paths.audit_dir.join(format!("audit-{today}.jsonl")));
            }

            let mut overall_ok = true;
            for f in &files {
                if !f.exists() {
                    println!("{}: missing", f.display());
                    overall_ok = false;
                    continue;
                }
                match hatch_audit::verify_chain(f) {
                    Ok(report) => {
                        if report.ok() {
                            println!("{}: ok ({} events)", f.display(), report.events);
                        } else {
                            overall_ok = false;
                            println!(
                                "{}: FAIL ({} events, {} malformed, {} mismatches)",
                                f.display(),
                                report.events,
                                report.malformed_lines,
                                report.mismatches.len()
                            );
                            for m in &report.mismatches {
                                println!(
                                    "  line {} ({}): expected {:?}, got {:?}",
                                    m.line, m.event_id, m.expected, m.actual
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!("{}: error: {e}", f.display());
                        overall_ok = false;
                    }
                }
            }
            Ok(if overall_ok { 0 } else { 1 })
        }
        DebugCmd::Profile { name } => cmd_debug_profile(paths, &name, format).await,
    }
}

async fn cmd_debug_profile(paths: &DaemonPaths, name: &str, format: OutputFormat) -> Result<u8> {
    let row = hatch_state::Store::open(&paths.db_path)
        .ok()
        .and_then(|store| store.get_manifest_latest(name).ok().flatten());
    let toml = match row {
        Some(r) => r.content,
        None => {
            eprintln!("hatch: not installed or unreadable: {name}");
            return Ok(ErrorCode::NotFound as u8);
        }
    };
    let manifest = Manifest::parse_str(&toml)?;
    let ctx = hatch_core::template::TemplateContext::from_env();
    let policy = hatch_core::compile::compile(&manifest, &ctx)?;

    match format {
        OutputFormat::Json => {
            let payload = serde_json::json!({
                "name": manifest.name,
                "version": manifest.version,
                "risk_score": policy.risk_score,
                "resolved_paths_read": policy.resolved_paths_read,
                "resolved_paths_write": policy.resolved_paths_write,
                "network_https_exact": policy.network_allow.https_exact,
                "network_https_suffix": policy.network_allow.https_suffix,
                "network_dns_exact": policy.network_allow.dns_exact,
                "network_dns_suffix": policy.network_allow.dns_suffix,
                "allow_http": policy.network_allow.allow_http,
                "tool_rules": policy.tool_rules.len(),
                "response_filters": policy.response_filters.len(),
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Text => {
            println!("manifest:    {} {}", manifest.name, manifest.version);
            println!(
                "risk:        {} ({})",
                policy.risk_score, policy.validation.risk_level
            );
            println!("network:");
            for h in &policy.network_allow.https_exact {
                println!("  https  exact:    {h}");
            }
            for h in &policy.network_allow.https_suffix {
                println!("  https  *.suffix: {h}");
            }
            for h in &policy.network_allow.dns_exact {
                println!("  dns    exact:    {h}");
            }
            for h in &policy.network_allow.dns_suffix {
                println!("  dns    *.suffix: {h}");
            }
            if policy.network_allow.allow_http {
                println!("  http   ALLOWED (plaintext)");
            }
            println!("filesystem:");
            for p in &policy.resolved_paths_read {
                println!("  read:  {}", p.display());
            }
            for p in &policy.resolved_paths_write {
                println!("  write: {}", p.display());
            }
            println!("tool rules: {}", policy.tool_rules.len());
            println!("response filters: {}", policy.response_filters.len());
            if cfg!(target_os = "macos") {
                let runtime = paths.runtime_dir.to_string_lossy().into_owned();
                let sbpl =
                    hatch_sandbox_macos::render_sandbox_exec_profile(&policy, &runtime, 0, 0);
                println!("\n--- sandbox-exec profile ---\n{sbpl}");
            }
        }
    }
    Ok(0)
}

fn cmd_config(c: ConfigCmd, paths: &DaemonPaths) -> Result<u8> {
    match c {
        ConfigCmd::Status { workspace } => {
            let mut specs = HostSpec::all_known(None);
            if workspace {
                specs.push(workspace_cursor_spec(None)?);
            }
            for spec in &specs {
                let s = hostcfg_status(spec);
                println!(
                    "{:<14}  exists={:<5} wrapped={:<5} servers={:>3}  {}",
                    s.host,
                    s.exists,
                    s.wrapped,
                    s.mcp_server_count,
                    s.path.display()
                );
            }
            Ok(0)
        }
        ConfigCmd::Sync {
            host,
            shim_path,
            force,
            workspace,
            workspace_path,
        } => {
            let specs = if workspace || workspace_path.is_some() {
                vec![workspace_cursor_spec(workspace_path.as_deref())?]
            } else {
                filtered_hosts(host)?
            };
            let shim = shim_path.unwrap_or_else(default_shim_path);
            let opts = RewriteOptions {
                shim_path: shim,
                force,
                state_dir: Some(paths.state_dir.to_string_lossy().into_owned()),
            };
            for spec in specs {
                let label = host_label(&spec);
                match hostcfg_sync(&spec, &opts) {
                    Ok(report) if report.skipped => {
                        println!(
                            "{:<14}  skipped (no config at {})",
                            label,
                            spec.path.display()
                        );
                    }
                    Ok(report) => {
                        println!(
                            "{:<14}  wrapped {} server(s)  backup={}",
                            label,
                            report.wrapped_servers.len(),
                            report
                                .backup_path
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "(none)".into())
                        );
                    }
                    Err(e) => println!("{:<14}  error: {e}", label),
                }
            }
            Ok(0)
        }
        ConfigCmd::Unsync {
            host,
            workspace,
            workspace_path,
        } => {
            let specs = if workspace || workspace_path.is_some() {
                vec![workspace_cursor_spec(workspace_path.as_deref())?]
            } else {
                filtered_hosts(host)?
            };
            for spec in specs {
                let label = host_label(&spec);
                match hostcfg_restore(&spec) {
                    Ok(report) => println!(
                        "{:<14}  restored {} server(s)",
                        label,
                        report.wrapped_servers.len()
                    ),
                    Err(e) => println!("{:<14}  error: {e}", label),
                }
            }
            Ok(0)
        }
    }
}

fn host_label(spec: &HostSpec) -> String {
    if spec.kind == HostKind::Cursor {
        let home_cursor = dirs::home_dir().map(|h| h.join(".cursor/mcp.json"));
        if home_cursor.as_deref() != Some(spec.path.as_path()) {
            return "cursor[ws]".to_string();
        }
    }
    spec.kind.slug().to_string()
}

fn workspace_cursor_spec(explicit: Option<&std::path::Path>) -> Result<HostSpec> {
    let dir = match explicit {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir().context("resolving current dir")?,
    };
    Ok(HostSpec {
        kind: HostKind::Cursor,
        path: dir.join(".cursor").join("mcp.json"),
    })
}

fn filtered_hosts(filter: Option<String>) -> Result<Vec<HostSpec>> {
    let all = HostSpec::all_known(None);
    match filter {
        None => Ok(all),
        Some(name) => {
            let kind = match name.as_str() {
                "claude-desktop" => HostKind::ClaudeDesktop,
                "cursor" => HostKind::Cursor,
                "claude-code" => HostKind::ClaudeCode,
                "zed" => HostKind::Zed,
                "continue" => HostKind::Continue,
                "windsurf" => HostKind::Windsurf,
                _ => return Err(anyhow::anyhow!("unknown host {name:?}")),
            };
            Ok(all.into_iter().filter(|s| s.kind == kind).collect())
        }
    }
}

fn default_shim_path() -> String {
    "/usr/local/bin/hatch-shim".into()
}

fn cmd_registry(c: RegistrySubCmd, paths: &DaemonPaths, format: OutputFormat) -> Result<u8> {
    let cache = paths.state_dir.join("registry");
    let trust = hatch_core::sig::TrustStore::empty().with_unsigned(true);
    let registry = Registry::new(cache, trust);
    match c {
        RegistrySubCmd::InstallBundle { path } => {
            let loaded = registry
                .install_bundle_from_file(&path)
                .context("install bundle")?;
            println!(
                "installed {} manifest(s) (released {})",
                loaded.manifest.entries.len(),
                loaded.manifest.released_at
            );
            Ok(0)
        }
        RegistrySubCmd::List => {
            let entries = registry.list_local()?;
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&entries)?),
                OutputFormat::Text => {
                    if entries.is_empty() {
                        println!("no manifests in registry cache");
                    } else {
                        println!("{:<24} {:<10} {:>6}  PATH", "NAME", "VERSION", "RISK");
                        for e in &entries {
                            println!(
                                "{:<24} {:<10} {:>6}  {}",
                                e.name, e.version, e.risk_score, e.path
                            );
                        }
                    }
                }
            }
            Ok(0)
        }
        RegistrySubCmd::Verify { name } => {
            let m = registry.fetch_manifest(&name)?;
            match registry.verify_manifest(&m) {
                Ok(_) => {
                    println!("ok {}", m.name);
                    Ok(0)
                }
                Err(e) => {
                    eprintln!("hatch: verify {name}: {e}");
                    Ok(ErrorCode::SignatureFailed as u8)
                }
            }
        }
    }
}

async fn call_one(socket: &PathBuf, req: ClientRequest) -> Result<DaemonResponse> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connect daemon at {}", socket.display()))?;
    let (mut r, mut w) = stream.split();
    Codec::write_message(&mut w, &req).await?;
    let resp: DaemonResponse = Codec::read_message(&mut r).await?;
    Ok(resp)
}

fn expect_ok(resp: &DaemonResponse) -> Result<u8> {
    match resp {
        DaemonResponse::Ok => {
            println!("ok");
            Ok(0)
        }
        DaemonResponse::Error { code, message } => {
            eprintln!("hatch: {message}");
            Ok(*code as u8)
        }
        other => {
            eprintln!("hatch: unexpected: {other:?}");
            Ok(1)
        }
    }
}

fn bail_resp(other: DaemonResponse) -> Result<u8> {
    eprintln!("hatch: unexpected daemon response: {other:?}");
    Ok(1)
}

fn print_status(resp: &DaemonResponse, format: OutputFormat) -> Result<u8> {
    match resp {
        DaemonResponse::DaemonStatus {
            uptime_seconds,
            running_servers,
            version,
        } => {
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string(resp)?),
                OutputFormat::Text => {
                    println!("hatch daemon");
                    println!("  version:         {version}");
                    println!("  uptime:          {uptime_seconds}s");
                    println!("  running servers: {running_servers}");
                }
            }
            Ok(0)
        }
        DaemonResponse::Error { code, message } => {
            eprintln!("hatch: {message}");
            Ok(*code as u8)
        }
        other => bail_resp(other.clone()),
    }
}

fn print_list(resp: &DaemonResponse, format: OutputFormat) -> Result<u8> {
    match resp {
        DaemonResponse::Manifests { items } => {
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string(items)?),
                OutputFormat::Text => {
                    if items.is_empty() {
                        println!("no manifests installed");
                    } else {
                        println!(
                            "{:<24} {:<10} {:<10} {:>6}  SIGNED",
                            "NAME", "VERSION", "SOURCE", "RISK"
                        );
                        for m in items {
                            println!(
                                "{:<24} {:<10} {:<10} {:>6}  {}",
                                m.name,
                                m.version,
                                m.source,
                                m.risk_score,
                                if m.signature_verified { "yes" } else { "no" },
                            );
                        }
                    }
                }
            }
            Ok(0)
        }
        DaemonResponse::Error { code, message } => {
            eprintln!("hatch: {message}");
            Ok(*code as u8)
        }
        other => bail_resp(other.clone()),
    }
}

fn print_ps(resp: &DaemonResponse, format: OutputFormat) -> Result<u8> {
    match resp {
        DaemonResponse::RunningServers { items } => {
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string(items)?),
                OutputFormat::Text => {
                    if items.is_empty() {
                        println!("no running servers");
                    } else {
                        println!(
                            "{:<36} {:<18} {:<8} {:<8} STATUS",
                            "ID", "MANIFEST", "BACKEND", "PID"
                        );
                        for s in items {
                            println!(
                                "{:<36} {:<18} {:<8} {:<8} {}",
                                s.id, s.manifest_name, s.sandbox_backend, s.pid, s.status
                            );
                        }
                    }
                }
            }
            Ok(0)
        }
        DaemonResponse::Error { code, message } => {
            eprintln!("hatch: {message}");
            Ok(*code as u8)
        }
        other => bail_resp(other.clone()),
    }
}

fn print_audit(resp: &DaemonResponse, format: OutputFormat) -> Result<u8> {
    match resp {
        DaemonResponse::AuditEvents { events, .. } => {
            match format {
                OutputFormat::Json => {
                    for ev in events {
                        println!("{}", serde_json::to_string(ev)?);
                    }
                }
                OutputFormat::Text => {
                    for ev in events {
                        println!(
                            "{}  {:<22} {:<24} {}",
                            ev.ts,
                            ev.event,
                            ev.server,
                            serde_json::to_string(&ev.fields).unwrap_or_default()
                        );
                    }
                }
            }
            Ok(0)
        }
        DaemonResponse::Error { code, message } => {
            eprintln!("hatch: {message}");
            Ok(*code as u8)
        }
        other => bail_resp(other.clone()),
    }
}

fn print_inspect(resp: &DaemonResponse, format: OutputFormat) -> Result<u8> {
    match resp {
        DaemonResponse::AuditEvents { events, .. } => {
            if let Some(ev) = events.first() {
                match format {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(ev)?),
                    OutputFormat::Text => {
                        println!("server: {}", ev.server);
                        for (k, v) in &ev.fields {
                            println!("  {k}: {v}");
                        }
                    }
                }
            }
            Ok(0)
        }
        DaemonResponse::Error { code, message } => {
            eprintln!("hatch: {message}");
            Ok(*code as u8)
        }
        other => bail_resp(other.clone()),
    }
}

async fn cmd_run(socket: &PathBuf, name: &str, seconds: u64) -> Result<u8> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connect daemon at {}", socket.display()))?;
    let (mut r, mut w) = stream.split();
    Codec::write_message(
        &mut w,
        &ClientRequest::SpawnManual {
            name: name.to_string(),
        },
    )
    .await?;

    let resp: DaemonResponse = Codec::read_message(&mut r).await?;
    let server_id = match resp {
        DaemonResponse::Spawned {
            server_id,
            sandbox_backend,
        } => {
            eprintln!("hatch: spawned {name} as {server_id} via backend {sandbox_backend}");
            server_id
        }
        DaemonResponse::Error { code, message } => {
            eprintln!("hatch: {message}");
            return Ok(code as u8);
        }
        other => {
            eprintln!("hatch: unexpected: {other:?}");
            return Ok(1);
        }
    };

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(seconds);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let next =
            tokio::time::timeout(remaining, Codec::read_message::<_, DaemonResponse>(&mut r)).await;
        match next {
            Ok(Ok(DaemonResponse::ShimStdoutChunk { data, .. })) => {
                use tokio::io::AsyncWriteExt as _;
                tokio::io::stdout().write_all(&data).await.ok();
            }
            Ok(Ok(DaemonResponse::ShimStderrChunk { data, .. })) => {
                use tokio::io::AsyncWriteExt as _;
                tokio::io::stderr().write_all(&data).await.ok();
            }
            Ok(Ok(DaemonResponse::ShimServerExit { exit_code, .. })) => {
                eprintln!("hatch: server {server_id} exited with {exit_code:?}");
                return Ok(0);
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }
    eprintln!("hatch: detaching from {server_id} after {seconds}s");
    Ok(0)
}

async fn cmd_manifest_show(socket: &PathBuf, name: &str) -> Result<u8> {
    let resp = call_one(socket, ClientRequest::ListManifests).await?;
    match resp {
        DaemonResponse::Manifests { items } => {
            let found = items.iter().find(|i| i.name == name);
            match found {
                Some(m) => {
                    println!("{} {} ({})", m.name, m.version, m.source);
                    println!("  signed:     {}", m.signature_verified);
                    println!("  risk score: {}", m.risk_score);
                    println!("  installed:  {}", m.installed_at);
                    Ok(0)
                }
                None => {
                    eprintln!("hatch: not installed: {name}");
                    Ok(ErrorCode::NotFound as u8)
                }
            }
        }
        other => bail_resp(other),
    }
}

async fn cmd_manifest_edit(
    socket: &PathBuf,
    paths: &DaemonPaths,
    name: &str,
    allow_unsigned: bool,
) -> Result<u8> {
    let store = hatch_state::Store::open(&paths.db_path)
        .with_context(|| format!("opening state db at {}", paths.db_path.display()))?;
    let row = match store.get_manifest_latest(name)? {
        Some(r) => r,
        None => {
            eprintln!("hatch: not installed: {name}");
            return Ok(ErrorCode::NotFound as u8);
        }
    };

    let tmp_dir = std::env::temp_dir();
    let tmp = tmp_dir.join(format!("hatch-edit-{}-{}.toml", name, std::process::id()));
    std::fs::write(&tmp, &row.content)?;
    let original = row.content.clone();

    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());

    let status = std::process::Command::new(&editor).arg(&tmp).status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            eprintln!("hatch: editor {editor} exited with {s}");
            let _ = std::fs::remove_file(&tmp);
            return Ok(1);
        }
        Err(e) => {
            eprintln!("hatch: failed to launch editor {editor}: {e}");
            let _ = std::fs::remove_file(&tmp);
            return Ok(1);
        }
    }

    let edited = std::fs::read_to_string(&tmp)?;
    if edited == original {
        eprintln!("hatch: no changes");
        let _ = std::fs::remove_file(&tmp);
        return Ok(0);
    }

    let parsed = match Manifest::parse_str(&edited) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("hatch: edit rejected, manifest does not parse: {e}");
            eprintln!("       (your changes remain at {})", tmp.display());
            return Ok(2);
        }
    };
    if parsed.name != name {
        eprintln!(
            "hatch: edit rejected, manifest name changed from {} to {}",
            name, parsed.name
        );
        return Ok(2);
    }
    let report = validate::validate(&parsed);
    if !report.errors.is_empty() {
        eprintln!("hatch: edit rejected, validation errors:");
        for err in &report.errors {
            eprintln!("  {err:?}");
        }
        eprintln!("       (your changes remain at {})", tmp.display());
        return Ok(2);
    }

    let final_path = tmp.clone();
    let resp = call_one(
        socket,
        ClientRequest::Install {
            source: InstallSource::File {
                path: final_path.to_string_lossy().into_owned(),
            },
            allow_unsigned,
        },
    )
    .await?;
    let code = expect_ok(&resp)?;
    let _ = std::fs::remove_file(&tmp);
    if code == 0 {
        println!("ok edited {} -> {}", name, parsed.version);
    }
    Ok(code)
}

async fn cmd_manifest_diff(socket: &PathBuf, name: &str, file: &PathBuf) -> Result<u8> {
    let _ = socket;
    let local = Manifest::parse_file(file)?;
    let local_report = validate::validate(&local);
    let local_risk = local_report.risk_score;
    let resp = call_one(socket, ClientRequest::ListManifests).await?;
    if let DaemonResponse::Manifests { items } = resp {
        if let Some(installed) = items.iter().find(|i| i.name == name) {
            println!(
                "installed:  version={} risk={}",
                installed.version, installed.risk_score
            );
            println!(
                "file:       version={} risk={} delta={:+}",
                local.version,
                local_risk,
                local_risk as i64 - installed.risk_score as i64
            );
        } else {
            println!("file:       version={} risk={}", local.version, local_risk);
            println!("installed:  (not installed)");
        }
    }
    Ok(0)
}

fn cmd_manifest_validate(path: &PathBuf, format: OutputFormat) -> Result<u8> {
    let m = Manifest::parse_file(path)?;
    let report = validate::validate(&m);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Text => {
            if report.ok() {
                println!(
                    "ok  {} {} (risk {} / {})",
                    m.name, m.version, report.risk_score, report.risk_level
                );
            } else {
                println!("invalid  {} {}", m.name, m.version);
            }
            for w in &report.warnings {
                println!("  warning  {}: {}", w.field, w.message);
            }
            for e in &report.errors {
                println!("  error    {}: {}", e.field, e.message);
            }
        }
    }
    if report.ok() {
        Ok(0)
    } else {
        Ok(ErrorCode::ManifestInvalid as u8)
    }
}

fn cmd_manifest_explain(path: &PathBuf, format: OutputFormat) -> Result<u8> {
    let m = Manifest::parse_file(path)?;
    let report = validate::validate(&m);
    let breakdown = hatch_core::risk::breakdown(&m);
    match format {
        OutputFormat::Json => {
            let payload = serde_json::json!({
                "name": m.name,
                "version": m.version,
                "description": m.description,
                "signed": m.signature.is_some(),
                "risk_score": report.risk_score,
                "risk_level": report.risk_level,
                "warnings": report.warnings,
                "errors": report.errors,
                "breakdown": breakdown.entries,
                "network_allow_https": m.network.allow_https,
                "network_allow_dns": m.network.allow_dns,
                "filesystem_read": m.filesystem.read,
                "filesystem_write": m.filesystem.write,
                "exec_allow_subprocess": m.exec.allow_subprocess,
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Text => {
            println!("{} {}", m.name, m.version);
            if !m.description.is_empty() {
                println!("  {}", m.description);
            }
            println!("  signed:      {}", m.signature.is_some());
            println!(
                "  risk:        {} ({})",
                report.risk_score, report.risk_level
            );
            if !m.network.allow_https.is_empty() {
                println!("  network (https):");
                for h in &m.network.allow_https {
                    println!("    - {h}");
                }
            }
            if !m.filesystem.read.is_empty() {
                println!("  filesystem (read):");
                for p in &m.filesystem.read {
                    println!("    - {p}");
                }
            }
            if !m.filesystem.write.is_empty() {
                println!("  filesystem (write):");
                for p in &m.filesystem.write {
                    println!("    - {p}");
                }
            }
            if m.exec.allow_subprocess {
                println!("  subprocess: allowed");
                for b in &m.exec.allow_binaries {
                    println!("    - {b}");
                }
            }
            if !breakdown.entries.is_empty() {
                println!("  score breakdown:");
                for (label, delta) in &breakdown.entries {
                    println!("    {:+5}  {label}", delta);
                }
            }
            for w in &report.warnings {
                println!("  warning  {}: {}", w.field, w.message);
            }
            for e in &report.errors {
                println!("  error    {}: {}", e.field, e.message);
            }
        }
    }
    if report.ok() {
        Ok(0)
    } else {
        Ok(ErrorCode::ManifestInvalid as u8)
    }
}

fn cmd_doctor(socket: &std::path::Path, paths: &DaemonPaths) -> Result<u8> {
    println!("hatch doctor");
    println!("  state_dir:   {}", paths.state_dir.display());
    println!("  runtime_dir: {}", paths.runtime_dir.display());
    println!("  audit_dir:   {}", paths.audit_dir.display());
    println!("  db_path:     {}", paths.db_path.display());
    println!("  socket:      {}", socket.display());
    println!("  state dir exists: {}", paths.state_dir.exists());
    println!("  socket reachable: {}", socket.exists());

    #[cfg(target_os = "linux")]
    {
        let cap = hatch_sandbox_linux::detect_capabilities();
        println!("  linux capabilities:");
        println!("    user_namespaces:  {}", cap.user_namespaces);
        println!("    mount_namespaces: {}", cap.mount_namespaces);
        println!("    net_namespaces:   {}", cap.net_namespaces);
        println!("    pid_namespaces:   {}", cap.pid_namespaces);
        println!("    cgroups_v2:       {}", cap.cgroups_v2);
        println!(
            "    landlock:         {}",
            cap.landlock
                .map(|v| format!("v{v}"))
                .unwrap_or_else(|| "no".into())
        );
    }

    Ok(0)
}
