#![deny(clippy::all)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use hatch_ipc::{ClientRequest, Codec, DaemonPaths, DaemonResponse, PolicyDecision};
use hatch_protocol::jsonrpc::{parse_message, Id, ParsedMessage, Response, RpcError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "hatch-shim",
    version,
    about = "Bridge between MCP host and hatch daemon"
)]
struct Args {
    #[arg(long, env = "HATCH_SERVER")]
    server: Option<String>,

    #[arg(long, env = "HATCH_HOST")]
    host: Option<String>,

    #[arg(long, env = "HATCH_SOCKET")]
    socket: Option<PathBuf>,

    #[arg(long, env = "HATCH_STATE_DIR")]
    state_dir: Option<PathBuf>,

    #[arg(long, env = "HATCH_MEDIATE", default_value_t = true)]
    mediate: bool,
}

fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("HATCH_LOG").unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();

    let args = Args::parse();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hatch-shim: tokio init: {e}");
            return ExitCode::from(1);
        }
    };
    match rt.block_on(run(args)) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("hatch-shim: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(args: Args) -> Result<u8> {
    let server = args
        .server
        .clone()
        .ok_or_else(|| anyhow::anyhow!("HATCH_SERVER env var or --server is required"))?;
    let host = args.host.clone().unwrap_or_else(|| "unknown".to_string());

    let paths = match &args.state_dir {
        Some(p) => DaemonPaths::from_state_root(p),
        None => DaemonPaths::default_for_user(),
    };
    let socket = args.socket.unwrap_or_else(|| paths.socket_path.clone());

    let stream = UnixStream::connect(&socket)
        .await
        .with_context(|| format!("connect daemon at {}", socket.display()))?;
    let (mut read_half, write_half) = stream.into_split();
    let writer = Arc::new(Mutex::new(write_half));

    {
        let mut w = writer.lock().await;
        Codec::write_message(
            &mut *w,
            &ClientRequest::SpawnSandboxed {
                name: server.clone(),
                host: host.clone(),
            },
        )
        .await?;
    }

    let resp: DaemonResponse = Codec::read_message(&mut read_half).await?;
    let server_id = match resp {
        DaemonResponse::Spawned { server_id, .. } => server_id,
        DaemonResponse::Error { message, .. } => {
            eprintln!("hatch-shim: spawn failed: {message}");
            return Ok(15);
        }
        other => {
            eprintln!("hatch-shim: unexpected: {other:?}");
            return Ok(1);
        }
    };

    let mediate = args.mediate;
    let writer_for_stdin = writer.clone();
    let server_id_for_stdin = server_id.clone();
    let host_to_server = tokio::spawn(async move {
        host_to_server_loop(writer_for_stdin, server_id_for_stdin, mediate).await
    });

    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut exit_code: i32 = 0;
    loop {
        let msg: DaemonResponse = match Codec::read_message(&mut read_half).await {
            Ok(m) => m,
            Err(hatch_ipc::IpcError::ShortRead) => break,
            Err(e) => {
                eprintln!("hatch-shim: ipc read: {e}");
                break;
            }
        };
        match msg {
            DaemonResponse::ShimStdoutChunk { data, .. } => {
                stdout.write_all(&data).await.ok();
                stdout.flush().await.ok();
            }
            DaemonResponse::ShimStderrChunk { data, .. } => {
                stderr.write_all(&data).await.ok();
                stderr.flush().await.ok();
            }
            DaemonResponse::ShimServerExit {
                exit_code: code, ..
            } => {
                exit_code = code.unwrap_or(0);
                break;
            }
            DaemonResponse::Error { code, message } => {
                eprintln!("hatch-shim: daemon error ({code:?}): {message}");
                exit_code = code as i32;
                break;
            }
            _ => {}
        }
    }
    let _ = host_to_server.await;
    Ok(clamp_exit(exit_code))
}

async fn host_to_server_loop(
    writer: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    server_id: String,
    mediate: bool,
) {
    let mut stdin = tokio::io::stdin();
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        let n = match stdin.read(&mut chunk).await {
            Ok(0) => {
                send_eof(&writer, &server_id).await;
                return;
            }
            Ok(n) => n,
            Err(_) => return,
        };
        buf.extend_from_slice(&chunk[..n]);
        process_buffer(&mut buf, &writer, &server_id, mediate).await;
    }
}

async fn process_buffer(
    buf: &mut Vec<u8>,
    writer: &Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    server_id: &str,
    mediate: bool,
) {
    loop {
        let nl = match buf.iter().position(|b| *b == b'\n') {
            Some(p) => p,
            None => return,
        };
        let line: Vec<u8> = buf.drain(..=nl).collect();
        let trimmed = trim_newline(&line);
        if trimmed.is_empty() {
            continue;
        }
        if mediate {
            if let Err(handled) = mediate_message(trimmed, writer, server_id).await {
                if handled {
                    continue;
                }
            }
        }
        send_stdin_chunk(writer, server_id, &line).await;
    }
}

async fn mediate_message(
    bytes: &[u8],
    writer: &Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    server_id: &str,
) -> std::result::Result<(), bool> {
    let parsed = match parse_message(bytes) {
        Ok(p) => p,
        Err(_) => return Err(false),
    };
    let tool = match parsed.tool_call_name() {
        Some(t) => t.to_string(),
        None => return Err(false),
    };
    let args = parsed.tool_call_args();
    let _req_id = match &parsed {
        ParsedMessage::Request(r) => r.id.clone(),
        _ => None,
    };

    let mut w = writer.lock().await;
    let policy_req = ClientRequest::PolicyQuery {
        server_id: server_id.to_string(),
        tool: tool.clone(),
        args: args.clone(),
    };
    if Codec::write_message(&mut *w, &policy_req).await.is_err() {
        return Err(false);
    }
    drop(w);

    Ok(())
}

async fn send_eof(writer: &Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>, server_id: &str) {
    let mut w = writer.lock().await;
    let _ = Codec::write_message(
        &mut *w,
        &ClientRequest::ShimStdinEof {
            server_id: server_id.to_string(),
        },
    )
    .await;
}

async fn send_stdin_chunk(
    writer: &Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    server_id: &str,
    data: &[u8],
) {
    let mut w = writer.lock().await;
    let _ = Codec::write_message(
        &mut *w,
        &ClientRequest::ShimStdin {
            server_id: server_id.to_string(),
            data: data.to_vec(),
        },
    )
    .await;
}

fn trim_newline(s: &[u8]) -> &[u8] {
    let mut end = s.len();
    while end > 0 && (s[end - 1] == b'\n' || s[end - 1] == b'\r') {
        end -= 1;
    }
    &s[..end]
}

fn clamp_exit(code: i32) -> u8 {
    if !(0..=255).contains(&code) {
        1
    } else {
        code as u8
    }
}

#[allow(dead_code)]
fn synth_deny_response(id: Id, reason: &str) -> Vec<u8> {
    let r = Response {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(RpcError {
            code: -32603,
            message: format!("hatch denied: {reason}"),
            data: None,
        }),
    };
    let mut s = serde_json::to_vec(&r).unwrap_or_default();
    s.push(b'\n');
    s
}

#[allow(dead_code)]
fn unwrap_decision(decision: PolicyDecision) -> bool {
    matches!(decision, PolicyDecision::Allow)
}
