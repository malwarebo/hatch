use std::net::SocketAddr;
use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use prometheus::{
    register_counter_vec_with_registry, register_gauge_with_registry,
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_counter_with_registry, register_int_gauge_with_registry, CounterVec, Encoder,
    Gauge, HistogramVec, IntCounter, IntCounterVec, IntGauge, Registry, TextEncoder,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

#[allow(dead_code)]
pub struct Metrics {
    pub registry: Registry,
    pub uptime_seconds: Gauge,
    pub servers_running: IntGauge,
    pub servers_spawned_total: IntCounterVec,
    pub tool_calls_total: IntCounterVec,
    pub fs_denials_total: IntCounterVec,
    pub net_attempts_total: IntCounterVec,
    pub proxy_bytes_total: CounterVec,
    pub approval_latency_seconds: HistogramVec,
    pub tool_call_latency_seconds: HistogramVec,
    pub audit_events_total: IntCounterVec,
    pub audit_write_errors_total: IntCounter,
}

static GLOBAL: OnceLock<Metrics> = OnceLock::new();

pub fn init() -> &'static Metrics {
    GLOBAL.get_or_init(build)
}

pub fn get() -> Option<&'static Metrics> {
    GLOBAL.get()
}

fn build() -> Metrics {
    let registry = Registry::new();
    let uptime_seconds =
        register_gauge_with_registry!("hatch_daemon_uptime_seconds", "Daemon uptime (s)", registry)
            .expect("register uptime");
    let servers_running = register_int_gauge_with_registry!(
        "hatch_servers_running",
        "Currently running sandboxed servers",
        registry
    )
    .expect("register running");
    let servers_spawned_total = register_int_counter_vec_with_registry!(
        "hatch_servers_spawned_total",
        "Spawned servers since daemon start",
        &["server"],
        registry
    )
    .expect("register spawned");
    let tool_calls_total = register_int_counter_vec_with_registry!(
        "hatch_tool_calls_total",
        "Tool calls inspected by policy engine",
        &["server", "tool", "decision"],
        registry
    )
    .expect("register tool calls");
    let fs_denials_total = register_int_counter_vec_with_registry!(
        "hatch_fs_denials_total",
        "Filesystem denials",
        &["server", "op"],
        registry
    )
    .expect("register fs denials");
    let net_attempts_total = register_int_counter_vec_with_registry!(
        "hatch_net_attempts_total",
        "Network attempts inspected by SNI proxy",
        &["server", "decision"],
        registry
    )
    .expect("register net attempts");
    let proxy_bytes_total = register_counter_vec_with_registry!(
        "hatch_proxy_bytes_total",
        "Bytes pumped by SNI proxy",
        &["server", "direction"],
        registry
    )
    .expect("register proxy bytes");
    let approval_latency_seconds = register_histogram_vec_with_registry!(
        "hatch_approval_latency_seconds",
        "End-to-end approval latency",
        &["server"],
        registry
    )
    .expect("register approval latency");
    let tool_call_latency_seconds = register_histogram_vec_with_registry!(
        "hatch_tool_call_latency_seconds",
        "Tool-call shim overhead",
        &["server", "tool"],
        registry
    )
    .expect("register tool latency");
    let audit_events_total = register_int_counter_vec_with_registry!(
        "hatch_audit_events_total",
        "Audit events written",
        &["event_type"],
        registry
    )
    .expect("register audit total");
    let audit_write_errors_total = register_int_counter_with_registry!(
        "hatch_audit_write_errors_total",
        "Audit write errors",
        registry
    )
    .expect("register audit errors");

    Metrics {
        registry,
        uptime_seconds,
        servers_running,
        servers_spawned_total,
        tool_calls_total,
        fs_denials_total,
        net_attempts_total,
        proxy_bytes_total,
        approval_latency_seconds,
        tool_call_latency_seconds,
        audit_events_total,
        audit_write_errors_total,
    }
}

pub struct MetricsServer {
    #[allow(dead_code)]
    pub addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl MetricsServer {
    pub async fn start(bind: SocketAddr) -> Result<MetricsServer> {
        let _ = init();
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|e| anyhow!("bind metrics on {bind}: {e}"))?;
        let addr = listener.local_addr()?;
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        info!(target: "hatch::metrics", %addr, "Prometheus metrics endpoint listening");
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => {
                        info!(target: "hatch::metrics", "metrics shutdown");
                        return;
                    }
                    res = listener.accept() => {
                        if let Ok((mut stream, _)) = res {
                            tokio::spawn(async move {
                                if let Err(e) = handle_metrics_request(&mut stream).await {
                                    warn!(target: "hatch::metrics", "metrics request: {e}");
                                }
                            });
                        }
                    }
                }
            }
        });
        Ok(MetricsServer { addr, shutdown: tx })
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}

async fn handle_metrics_request(stream: &mut tokio::net::TcpStream) -> Result<()> {
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf).await?;

    let metrics = init();
    let encoder = TextEncoder::new();
    let mfs = metrics.registry.gather();
    let mut body = Vec::new();
    encoder
        .encode(&mfs, &mut body)
        .map_err(|e| anyhow!("encode: {e}"))?;

    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        encoder.format_type(),
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;
    Ok(())
}
