#![deny(clippy::all)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod approvals;
mod manifests;
mod metrics;
mod runner;
mod server;
mod state_layer;

#[derive(Debug, Parser)]
#[command(name = "hatch-daemon", version, about = "Long-running hatch daemon")]
struct Args {
    #[arg(long)]
    foreground: bool,

    #[arg(long)]
    launchd: bool,

    #[arg(long)]
    systemd: bool,

    #[arg(long, env = "HATCH_STATE_DIR")]
    state_dir: Option<PathBuf>,

    #[arg(long, env = "HATCH_SOCKET")]
    socket: Option<PathBuf>,

    #[arg(long, env = "HATCH_METRICS")]
    metrics_addr: Option<String>,

    #[arg(long, env = "HATCH_REAL_SANDBOX")]
    real_sandbox: bool,

    #[arg(long, env = "HATCH_ENABLE_PROXY")]
    enable_proxy: bool,
}

fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    let paths = if let Some(state_dir) = &args.state_dir {
        hatch_ipc::paths::DaemonPaths::from_state_root(state_dir)
    } else {
        hatch_ipc::paths::DaemonPaths::default_for_user()
    };
    let socket = args
        .socket
        .clone()
        .unwrap_or_else(|| paths.socket_path.clone());

    paths
        .ensure_dirs()
        .context("create daemon state directories")?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("hatch-daemon")
        .build()
        .context("build tokio runtime")?;

    let opts = server::DaemonOptions {
        metrics_addr: args.metrics_addr.clone(),
        real_sandbox: args.real_sandbox,
        enable_proxy: args.enable_proxy,
    };

    runtime.block_on(async move {
        let result = server::run(&paths, &socket, opts).await;
        if let Err(err) = &result {
            error!(target: "hatch::daemon", "fatal: {err:#}");
        }
        result
    })
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_env("HATCH_LOG").unwrap_or_else(|_| EnvFilter::new("info,hatch=debug"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
    info!(target: "hatch::daemon", "tracing initialised");
}

pub(crate) fn version_string() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
