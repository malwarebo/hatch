use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hatch_audit::{AuditWriter, EventBuilder, EventType};
use hatch_ipc::{
    AuditEventEnvelope, AuditFilter, ClientRequest, Codec, DaemonPaths, DaemonResponse, ErrorCode,
    PolicyDecision, RunningServerSummary,
};
use hatch_protocol::{filter as response_filter, policy as tool_policy};
use hatch_proxy::{ProxyRegistry, ProxyServer};
use hatch_state::Store;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, error, info, warn};

use crate::approvals::{ApprovalBroker, Decision};
use crate::manifests;
use crate::metrics;
use crate::runner::{Registry, Runner, StdinEvent};
use crate::state_layer::{DaemonState, DaemonStateInit};
use crate::version_string;

#[derive(Debug, Clone, Default)]
pub struct DaemonOptions {
    pub metrics_addr: Option<String>,
    pub real_sandbox: bool,
    pub enable_proxy: bool,
}

pub async fn run(paths: &DaemonPaths, socket: &Path, opts: DaemonOptions) -> Result<()> {
    if socket.exists() {
        std::fs::remove_file(socket).ok();
    }

    let store = Store::open(&paths.db_path).context("open state store")?;
    let crashed = store.mark_orphans_crashed().unwrap_or_else(|e| {
        warn!(target: "hatch::daemon", "mark_orphans_crashed: {e}");
        0
    });
    if crashed > 0 {
        warn!(target: "hatch::daemon", "{crashed} previously-running server(s) marked crashed");
    }
    let audit = AuditWriter::open(&paths.audit_dir, true).context("open audit writer")?;
    let _ = audit.seal_old_files();
    let _ = audit.write(
        EventBuilder::new(EventType::DaemonStart)
            .field("version", version_string())
            .field("pid", std::process::id()),
    );

    let proxy_registry = ProxyRegistry::new();

    let (proxy_handle, dns_handle, proxy_port, dns_port) = if opts.enable_proxy {
        let proxy_srv = ProxyServer {
            listen: "127.0.0.1:0".parse().unwrap(),
            registry: proxy_registry.clone(),
            events: None,
        };
        let p = proxy_srv.start().await.context("start proxy")?;
        let proxy_port = p.addr.port();
        let dns_handle = hatch_proxy::dns::start_dns_server(
            "127.0.0.1:0".parse().unwrap(),
            proxy_registry.clone(),
        )
        .await
        .context("start DNS")?;
        let dns_port = dns_handle.addr.port();
        info!(target: "hatch::daemon", proxy_port, dns_port, "egress layer ready");
        (Some(p), Some(dns_handle), proxy_port, dns_port)
    } else {
        (None, None, 0, 0)
    };

    let metrics_handle = match &opts.metrics_addr {
        Some(addr_str) => match addr_str.parse() {
            Ok(addr) => match metrics::MetricsServer::start(addr).await {
                Ok(h) => Some(h),
                Err(e) => {
                    warn!(target: "hatch::daemon", "metrics: {e}");
                    None
                }
            },
            Err(e) => {
                warn!(target: "hatch::daemon", "metrics addr {addr_str:?}: {e}");
                None
            }
        },
        None => None,
    };
    let _ = metrics::init();

    let broker = ApprovalBroker::new();
    let state = Arc::new(DaemonState::new(DaemonStateInit {
        paths: paths.clone(),
        store,
        audit,
        broker,
        proxy_registry,
        real_sandbox: opts.real_sandbox,
        proxy_port,
        dns_port,
    }));
    let registry = Arc::new(Registry::new());
    let runner = Arc::new(Runner::new(Arc::clone(&state), Arc::clone(&registry)));

    let listener = UnixListener::bind(socket)
        .with_context(|| format!("bind unix socket {}", socket.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600));
    }
    info!(target: "hatch::daemon", socket = %socket.display(), "listening");

    let (shutdown_tx, _) = broadcast::channel::<()>(4);

    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        if wait_for_shutdown_signal().await.is_ok() {
            let _ = signal_tx.send(());
        }
    });

    let uptime_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            if let Some(m) = metrics::get() {
                m.uptime_seconds.set(uptime_state.uptime_seconds() as f64);
            }
        }
    });

    loop {
        let mut rx = shutdown_tx.subscribe();
        tokio::select! {
            res = listener.accept() => {
                match res {
                    Ok((stream, _addr)) => {
                        let state = Arc::clone(&state);
                        let registry = Arc::clone(&registry);
                        let runner = Arc::clone(&runner);
                        let shutdown_tx = shutdown_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve_connection(stream, state, registry, runner, shutdown_tx).await {
                                debug!(target: "hatch::daemon", "client: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        error!(target: "hatch::daemon", "accept failed: {e}");
                    }
                }
            }
            _ = rx.recv() => {
                info!(target: "hatch::daemon", "shutdown requested");
                break;
            }
        }
    }

    let _ = state
        .audit
        .write(EventBuilder::new(EventType::DaemonStop).field("reason", "signal"));

    let snapshot = registry.all().await;
    for srv in snapshot {
        let _ = srv.stdin_tx.send(StdinEvent::Eof).await;
        let _ = state.store.set_status(&srv.id, "exited");
    }

    if let Some(h) = proxy_handle {
        h.shutdown().await;
    }
    if let Some(h) = dns_handle {
        h.shutdown().await;
    }
    if let Some(h) = metrics_handle {
        h.shutdown().await;
    }

    let _ = std::fs::remove_file(socket);
    Ok(())
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        tokio::select! {
            _ = sigterm.recv() => Ok(()),
            _ = sigint.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}

async fn serve_connection(
    stream: UnixStream,
    state: Arc<DaemonState>,
    registry: Arc<Registry>,
    runner: Arc<Runner>,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<()> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = read_half;
    let writer = Arc::new(Mutex::new(write_half));

    loop {
        let req: ClientRequest = match Codec::read_message(&mut reader).await {
            Ok(r) => r,
            Err(hatch_ipc::IpcError::ShortRead) => return Ok(()),
            Err(e) => {
                debug!(target: "hatch::daemon::ipc", "read: {e}");
                return Err(e.into());
            }
        };

        match req {
            ClientRequest::DaemonStatus => {
                let running = registry.all().await.len();
                if let Some(m) = metrics::get() {
                    m.servers_running.set(running as i64);
                }
                let resp = DaemonResponse::DaemonStatus {
                    uptime_seconds: state.uptime_seconds(),
                    running_servers: running,
                    version: version_string(),
                };
                send(&writer, &resp).await?;
            }
            ClientRequest::DaemonStop => {
                send(&writer, &DaemonResponse::Ok).await?;
                let _ = shutdown_tx.send(());
                return Ok(());
            }
            ClientRequest::ListManifests => match manifests::list(&state) {
                Ok(items) => send(&writer, &DaemonResponse::Manifests { items }).await?,
                Err(e) => send_err(&writer, ErrorCode::Internal, &format!("{e}")).await?,
            },
            ClientRequest::ListRunning => {
                let items = build_running_list(&state).await;
                send(&writer, &DaemonResponse::RunningServers { items }).await?;
            }
            ClientRequest::Install {
                source,
                allow_unsigned,
            } => match manifests::install(&state, &source, allow_unsigned) {
                Ok(out) => {
                    let _ = state.audit.write(
                        EventBuilder::new(EventType::ConfigSync)
                            .server(out.name.clone())
                            .field("op", "install")
                            .field("version", out.version.clone())
                            .field("risk_score", out.risk_score),
                    );
                    send(&writer, &DaemonResponse::Ok).await?;
                }
                Err((code, msg)) => send_err(&writer, code, &msg).await?,
            },
            ClientRequest::Uninstall { name } => match manifests::uninstall(&state, &name) {
                Ok(_) => send(&writer, &DaemonResponse::Ok).await?,
                Err(e) => send_err(&writer, ErrorCode::NotFound, &format!("{e}")).await?,
            },
            ClientRequest::SpawnManual { name } => {
                handle_spawn(&runner, &writer, &state, &name, None).await?;
            }
            ClientRequest::SpawnSandboxed { name, host } => {
                handle_spawn(&runner, &writer, &state, &name, Some(host)).await?;
            }
            ClientRequest::Stop { target } => match runner.stop(&target).await {
                Ok(_) => send(&writer, &DaemonResponse::Ok).await?,
                Err(e) => send_err(&writer, ErrorCode::NotFound, &format!("{e}")).await?,
            },
            ClientRequest::Inspect { target } => {
                let resp = match registry.get(&target).await {
                    Some(s) => {
                        let summary = serde_json::json!({
                            "id": s.id,
                            "manifest_name": s.manifest_name,
                            "pid": s.pid,
                            "backend": s.backend,
                            "risk_score": s.policy.risk_score,
                            "network_allow_https": s.policy.manifest.network.allow_https,
                            "filesystem_read": s.policy.manifest.filesystem.read,
                            "filesystem_write": s.policy.manifest.filesystem.write,
                            "tool_rules": s.policy.manifest.tool_policy.rules.len(),
                        });
                        DaemonResponse::AuditEvents {
                            events: vec![hatch_ipc::AuditEventEnvelope {
                                ts: OffsetDateTime::now_utc()
                                    .format(&Rfc3339)
                                    .unwrap_or_default(),
                                event_id: target.clone(),
                                server: s.manifest_name.clone(),
                                server_id: Some(s.id.clone()),
                                host: None,
                                event: "inspect".into(),
                                fields: serde_json::from_value(summary).unwrap_or_default(),
                            }],
                            more_pending: false,
                        }
                    }
                    None => DaemonResponse::Error {
                        code: ErrorCode::NotFound,
                        message: format!("no running server {target}"),
                    },
                };
                send(&writer, &resp).await?;
            }
            ClientRequest::Audit { filter, follow: _ } => {
                let events = collect_audit(&state, &filter).unwrap_or_default();
                send(
                    &writer,
                    &DaemonResponse::AuditEvents {
                        events,
                        more_pending: false,
                    },
                )
                .await?;
            }
            ClientRequest::PolicyQuery {
                server_id,
                tool,
                args,
            } => {
                let decision = evaluate_policy(&state, &registry, &server_id, &tool, &args).await;
                send(&writer, &DaemonResponse::PolicyDecision { decision }).await?;
            }
            ClientRequest::Approve {
                approval_id,
                remember,
            } => match state.broker.approve(&approval_id, remember).await {
                Some((server, tool, _)) => {
                    let _ = state.audit.write(
                        EventBuilder::new(EventType::ApprovalGranted)
                            .server(&server)
                            .field("approval_id", approval_id.clone())
                            .field("tool", tool),
                    );
                    send(&writer, &DaemonResponse::Ok).await?;
                }
                None => send_err(&writer, ErrorCode::NotFound, "no such pending approval").await?,
            },
            ClientRequest::Deny { approval_id } => match state.broker.deny(&approval_id).await {
                Some((server, tool, _)) => {
                    let _ = state.audit.write(
                        EventBuilder::new(EventType::ApprovalDenied)
                            .server(&server)
                            .field("approval_id", approval_id.clone())
                            .field("tool", tool),
                    );
                    send(&writer, &DaemonResponse::Ok).await?;
                }
                None => send_err(&writer, ErrorCode::NotFound, "no such pending approval").await?,
            },
            ClientRequest::ShimStdin { server_id, data } => {
                if let Some(s) = registry.get(&server_id).await {
                    let _ = s.stdin_tx.send(StdinEvent::Bytes(data)).await;
                }
            }
            ClientRequest::ShimStdinEof { server_id } => {
                if let Some(s) = registry.get(&server_id).await {
                    let _ = s.stdin_tx.send(StdinEvent::Eof).await;
                }
            }
            ClientRequest::Heartbeat => {
                send(&writer, &DaemonResponse::Heartbeat).await?;
            }
        }
    }
}

async fn evaluate_policy(
    state: &Arc<DaemonState>,
    registry: &Arc<Registry>,
    server_id: &str,
    tool: &str,
    args: &serde_json::Value,
) -> PolicyDecision {
    let Some(srv) = registry.get(server_id).await else {
        return PolicyDecision::Deny {
            reason: format!("unknown server {server_id}"),
        };
    };
    let args_hash = hatch_audit::args::hash(args);
    let args_summary = hatch_audit::args::summarize(args);

    if let Some(d) = state
        .broker
        .check_remembered(&srv.manifest_name, tool, &args_hash)
        .await
    {
        return match d {
            Decision::Allow => PolicyDecision::Allow,
            Decision::Deny => PolicyDecision::Deny {
                reason: "previously remembered".into(),
            },
            Decision::Timeout => PolicyDecision::Deny {
                reason: "approval timed out previously".into(),
            },
        };
    }

    let report = tool_policy::evaluate(&srv.policy, tool, args, &srv.manifest_name, "shim");
    let decision_label = match &report.decision {
        tool_policy::Decision::Allow => "allow",
        tool_policy::Decision::Deny { .. } => "deny",
        tool_policy::Decision::RequireApproval { .. } => "require_approval",
    };
    if let Some(m) = metrics::get() {
        m.tool_calls_total
            .with_label_values(&[&srv.manifest_name, tool, decision_label])
            .inc();
    }
    let _ = state.audit.write(
        EventBuilder::new(EventType::ToolCall)
            .server(&srv.manifest_name)
            .server_id(server_id)
            .field("tool", tool.to_string())
            .field("args_hash", args_hash.clone())
            .field("args_summary", args_summary.clone())
            .field("decision", decision_label)
            .field("latency_ms", report.elapsed_ms),
    );

    match report.decision {
        tool_policy::Decision::Allow => PolicyDecision::Allow,
        tool_policy::Decision::Deny { reason } => PolicyDecision::Deny { reason },
        tool_policy::Decision::RequireApproval { reason: _ } => {
            let (approval_id, mut rx) = state
                .broker
                .request(
                    server_id.to_string(),
                    srv.manifest_name.clone(),
                    tool.to_string(),
                    args_hash,
                    args_summary.clone(),
                )
                .await;

            let _ = state.audit.write(
                EventBuilder::new(EventType::ApprovalRequested)
                    .server(&srv.manifest_name)
                    .server_id(server_id)
                    .field("approval_id", approval_id.clone())
                    .field("tool", tool.to_string())
                    .field("args_summary", args_summary),
            );
            crate::approvals::notify_user(&srv.manifest_name, tool, &approval_id).await;

            let timeout =
                Duration::from_secs(srv.policy.manifest.resources.tool_call_timeout_seconds as u64);
            let outcome = tokio::time::timeout(timeout, &mut rx).await;
            let _ = response_filter::defaults();
            match outcome {
                Ok(Ok(Decision::Allow)) => PolicyDecision::Allow,
                Ok(Ok(Decision::Deny)) => PolicyDecision::Deny {
                    reason: "user denied".into(),
                },
                Ok(Ok(Decision::Timeout)) | Err(_) => {
                    state.broker.timeout(&approval_id).await;
                    PolicyDecision::Deny {
                        reason: "approval timed out".into(),
                    }
                }
                Ok(Err(_)) => PolicyDecision::Deny {
                    reason: "approval broker closed".into(),
                },
            }
        }
    }
}

async fn handle_spawn(
    runner: &Arc<Runner>,
    writer: &Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    state: &Arc<DaemonState>,
    name: &str,
    host: Option<String>,
) -> Result<()> {
    match runner.spawn(name, host).await {
        Ok(srv) => {
            if let Some(m) = metrics::get() {
                m.servers_spawned_total
                    .with_label_values(&[&srv.manifest_name])
                    .inc();
                m.servers_running.set(state.uptime_seconds() as i64 + 1);
            }
            let writer_for_stream = Arc::clone(writer);
            let id = srv.id.clone();
            send(
                writer,
                &DaemonResponse::Spawned {
                    server_id: id.clone(),
                    sandbox_backend: srv.backend.clone(),
                },
            )
            .await?;
            stream_server_io(srv, writer_for_stream).await;
            Ok(())
        }
        Err(e) => {
            send_err(writer, ErrorCode::SpawnFailed, &format!("{e}")).await?;
            Ok(())
        }
    }
}

async fn stream_server_io(
    srv: Arc<crate::runner::RunningServer>,
    writer: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
) {
    let id = srv.id.clone();

    let stdout_rx = srv.stdout_rx.lock().await.take();
    let stderr_rx = srv.stderr_rx.lock().await.take();
    let exit_rx = srv.exit_rx.lock().await.take();

    if let Some(mut rx) = stdout_rx {
        let writer = Arc::clone(&writer);
        let id = id.clone();
        tokio::spawn(async move {
            while let Some(chunk) = rx.recv().await {
                let _ = send(
                    &writer,
                    &DaemonResponse::ShimStdoutChunk {
                        server_id: id.clone(),
                        data: chunk,
                    },
                )
                .await;
            }
        });
    }
    if let Some(mut rx) = stderr_rx {
        let writer = Arc::clone(&writer);
        let id = id.clone();
        tokio::spawn(async move {
            while let Some(chunk) = rx.recv().await {
                let _ = send(
                    &writer,
                    &DaemonResponse::ShimStderrChunk {
                        server_id: id.clone(),
                        data: chunk,
                    },
                )
                .await;
            }
        });
    }
    if let Some(rx) = exit_rx {
        let writer = Arc::clone(&writer);
        tokio::spawn(async move {
            let code = rx.await.unwrap_or(None);
            let _ = send(
                &writer,
                &DaemonResponse::ShimServerExit {
                    server_id: id.clone(),
                    exit_code: code,
                },
            )
            .await;
        });
    }
}

async fn build_running_list(state: &Arc<DaemonState>) -> Vec<RunningServerSummary> {
    let rows = state.store.list_running(false).unwrap_or_default();
    rows.into_iter()
        .map(|r| RunningServerSummary {
            id: r.id,
            manifest_name: r.manifest_name,
            manifest_version: r.manifest_version,
            host: r.host,
            pid: r.pid.unwrap_or(0) as u32,
            sandbox_backend: r.sandbox_backend,
            started_at: OffsetDateTime::from_unix_timestamp(r.started_at)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH)
                .format(&Rfc3339)
                .unwrap_or_default(),
            status: r.status,
        })
        .collect()
}

fn collect_audit(
    state: &Arc<DaemonState>,
    filter: &AuditFilter,
) -> Result<Vec<AuditEventEnvelope>> {
    let dir = &state.paths.audit_dir;
    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.starts_with("audit-") && s.ends_with(".jsonl"))
                .unwrap_or(false)
        })
        .collect();
    entries.sort();
    let mut all = Vec::new();
    for path in entries {
        if let Ok((evs, _)) = hatch_audit::read_file(&path) {
            for ev in evs {
                all.push(ev);
            }
        }
    }

    let filtered: Vec<AuditEventEnvelope> = all
        .into_iter()
        .filter(|ev| {
            filter
                .server
                .as_ref()
                .map(|s| &ev.server == s)
                .unwrap_or(true)
        })
        .filter(|ev| {
            filter
                .event_type
                .as_ref()
                .map(|t| &ev.event == t)
                .unwrap_or(true)
        })
        .filter(|ev| match filter.since_seconds {
            None => true,
            Some(secs) => {
                let cutoff = OffsetDateTime::now_utc() - time::Duration::seconds(secs as i64);
                OffsetDateTime::parse(&ev.ts, &Rfc3339)
                    .map(|t| t >= cutoff)
                    .unwrap_or(true)
            }
        })
        .map(|ev| AuditEventEnvelope {
            ts: ev.ts,
            event_id: ev.event_id,
            server: ev.server,
            server_id: ev.server_id,
            host: ev.host,
            event: ev.event,
            fields: ev.fields,
        })
        .collect();

    let limit = filter.limit.unwrap_or(100);
    let n = filtered.len();
    let start = n.saturating_sub(limit);
    Ok(filtered[start..].to_vec())
}

async fn send(
    writer: &Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    msg: &DaemonResponse,
) -> Result<()> {
    let mut guard = writer.lock().await;
    Codec::write_message(&mut *guard, msg).await?;
    Ok(())
}

async fn send_err(
    writer: &Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    code: ErrorCode,
    message: &str,
) -> Result<()> {
    send(
        writer,
        &DaemonResponse::Error {
            code,
            message: message.to_string(),
        },
    )
    .await
}
