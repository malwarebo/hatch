use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hatch_ipc::{ClientRequest, Codec, DaemonResponse, InstallSource};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::timeout;

const FIXTURE: &str = include_str!("../fixtures/cat.toml");

#[tokio::test]
async fn end_to_end_spawn_and_audit() -> Result<()> {
    let tmp = TempDir::new()?;
    let state_dir = tmp.path().to_path_buf();
    let socket = state_dir.join("runtime/daemon.sock");

    let exe = locate_daemon()?;
    let mut child: Child = Command::new(exe)
        .arg("--foreground")
        .env("HATCH_STATE_DIR", &state_dir)
        .env("HATCH_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("spawn daemon")?;

    wait_for_socket(&socket).await?;

    let manifest_path = tmp.path().join("cat.toml");
    std::fs::write(&manifest_path, FIXTURE)?;

    let install_resp = roundtrip(
        &socket,
        ClientRequest::Install {
            source: InstallSource::File {
                path: manifest_path.to_string_lossy().into_owned(),
            },
            allow_unsigned: true,
        },
    )
    .await?;
    match install_resp {
        DaemonResponse::Ok => {}
        DaemonResponse::Error { message, .. } => {
            shutdown(&socket).await.ok();
            return Err(anyhow!("install failed: {message}"));
        }
        other => {
            shutdown(&socket).await.ok();
            return Err(anyhow!("install unexpected: {other:?}"));
        }
    }

    let list_resp = roundtrip(&socket, ClientRequest::ListManifests).await?;
    match list_resp {
        DaemonResponse::Manifests { items } => {
            assert!(items.iter().any(|m| m.name == "cattest"));
        }
        other => {
            shutdown(&socket).await.ok();
            return Err(anyhow!("list unexpected: {other:?}"));
        }
    }

    let received = spawn_and_collect(&socket, "cattest", b"hello hatch\n").await?;
    assert_eq!(received, b"hello hatch\n");

    let audit_resp = roundtrip(
        &socket,
        ClientRequest::Audit {
            filter: hatch_ipc::AuditFilter {
                server: None,
                event_type: None,
                since_seconds: Some(3600),
                limit: Some(50),
            },
            follow: false,
        },
    )
    .await?;
    match audit_resp {
        DaemonResponse::AuditEvents { events, .. } => {
            assert!(events.iter().any(|e| e.event == "server_spawn"));
            assert!(events.iter().any(|e| e.event == "server_exit"));
            assert!(events.iter().any(|e| e.event == "daemon_start"));
        }
        other => {
            shutdown(&socket).await.ok();
            return Err(anyhow!("audit unexpected: {other:?}"));
        }
    }

    shutdown(&socket).await?;
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    Ok(())
}

async fn spawn_and_collect(socket: &PathBuf, name: &str, input: &[u8]) -> Result<Vec<u8>> {
    let stream = UnixStream::connect(socket).await?;
    let (mut r, mut w) = stream.into_split();

    Codec::write_message(
        &mut w,
        &ClientRequest::SpawnSandboxed {
            name: name.into(),
            host: "test".into(),
        },
    )
    .await?;
    let spawned: DaemonResponse = Codec::read_message(&mut r).await?;
    let server_id = match spawned {
        DaemonResponse::Spawned { server_id, .. } => server_id,
        DaemonResponse::Error { message, .. } => return Err(anyhow!("spawn: {message}")),
        other => return Err(anyhow!("spawn unexpected: {other:?}")),
    };

    Codec::write_message(
        &mut w,
        &ClientRequest::ShimStdin {
            server_id: server_id.clone(),
            data: input.to_vec(),
        },
    )
    .await?;
    Codec::write_message(
        &mut w,
        &ClientRequest::ShimStdinEof {
            server_id: server_id.clone(),
        },
    )
    .await?;
    w.shutdown().await.ok();

    let mut bytes = Vec::new();
    loop {
        let msg: DaemonResponse =
            match timeout(Duration::from_secs(10), Codec::read_message(&mut r)).await {
                Ok(Ok(m)) => m,
                Ok(Err(_)) => break,
                Err(_) => return Err(anyhow!("timed out waiting for server output")),
            };
        match msg {
            DaemonResponse::ShimStdoutChunk { data, .. } => bytes.extend_from_slice(&data),
            DaemonResponse::ShimStderrChunk { .. } => {}
            DaemonResponse::ShimServerExit { .. } => break,
            _ => {}
        }
    }
    Ok(bytes)
}

async fn roundtrip(socket: &PathBuf, req: ClientRequest) -> Result<DaemonResponse> {
    let stream = UnixStream::connect(socket).await?;
    let (mut r, mut w) = stream.into_split();
    Codec::write_message(&mut w, &req).await?;
    let resp = Codec::read_message(&mut r).await?;
    Ok(resp)
}

async fn shutdown(socket: &PathBuf) -> Result<()> {
    let _ = roundtrip(socket, ClientRequest::DaemonStop).await;
    Ok(())
}

async fn wait_for_socket(socket: &PathBuf) -> Result<()> {
    for _ in 0..200 {
        if socket.exists() && UnixStream::connect(socket).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(anyhow!("daemon socket {} never appeared", socket.display()))
}

fn locate_daemon() -> Result<PathBuf> {
    let mut p = std::env::current_exe()?;
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    let candidate = p.join(if cfg!(windows) {
        "hatch-daemon.exe"
    } else {
        "hatch-daemon"
    });
    if candidate.exists() {
        Ok(candidate)
    } else {
        Err(anyhow!(
            "daemon binary not found at {} -- run `cargo build -p hatch-daemon` first",
            candidate.display()
        ))
    }
}
