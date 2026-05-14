use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::sni::{extract_sni, host_matches, SniError};
use crate::{EventSink, ProxyEvent, ProxyRegistry};

pub struct ProxyServer {
    pub listen: SocketAddr,
    pub registry: ProxyRegistry,
    pub events: Option<EventSink>,
}

pub struct ProxyServerHandle {
    pub addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl ProxyServerHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}

impl ProxyServer {
    pub async fn start(self) -> std::io::Result<ProxyServerHandle> {
        let listener = TcpListener::bind(self.listen).await?;
        let addr = listener.local_addr()?;
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let registry = self.registry.clone();
        let events = self.events.clone();
        info!(target: "hatch::proxy", %addr, "SNI proxy listening");
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => {
                        info!(target: "hatch::proxy", "proxy shutdown");
                        return;
                    }
                    res = listener.accept() => {
                        match res {
                            Ok((stream, peer)) => {
                                let registry = registry.clone();
                                let events = events.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle(stream, peer, registry, events).await {
                                        debug!(target: "hatch::proxy", "{e}");
                                    }
                                });
                            }
                            Err(e) => warn!(target: "hatch::proxy", "accept: {e}"),
                        }
                    }
                }
            }
        });
        Ok(ProxyServerHandle { addr, shutdown: tx })
    }
}

async fn handle(
    mut stream: TcpStream,
    peer: SocketAddr,
    registry: ProxyRegistry,
    events: Option<EventSink>,
) -> std::io::Result<()> {
    let mut hello = vec![0u8; 8192];
    let mut total = 0;
    let read_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if total >= hello.len() {
            warn!(target: "hatch::proxy", "ClientHello buffer overflow");
            return Ok(());
        }
        let timeout = read_deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return Ok(());
        }
        let n = match tokio::time::timeout(timeout, stream.read(&mut hello[total..])).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()),
        };
        total += n;
        match extract_sni(&hello[..total]) {
            Ok(host) => {
                if let Err(e) = forward(stream, &hello[..total], host, peer, registry, events).await
                {
                    debug!(target: "hatch::proxy", "forward: {e}");
                }
                return Ok(());
            }
            Err(SniError::Short { .. }) => continue,
            Err(other) => {
                debug!(target: "hatch::proxy", "SNI parse: {other}");
                return Ok(());
            }
        }
    }
}

async fn forward(
    mut client: TcpStream,
    hello: &[u8],
    host: String,
    _peer: SocketAddr,
    registry: ProxyRegistry,
    events: Option<EventSink>,
) -> std::io::Result<()> {
    let reg = match registry.lookup_first().await {
        Some(r) => r,
        None => {
            warn!(target: "hatch::proxy", host = %host, "no proxy registration");
            return Ok(());
        }
    };
    let allow_exact = &reg.allow.https_exact;
    let allow_suffix = &reg.allow.https_suffix;
    if !host_matches(allow_exact, allow_suffix, &host) {
        emit(
            &events,
            ProxyEvent::Denied {
                server: reg.server_name.clone(),
                host: host.clone(),
                reason: "not on allowlist".into(),
            },
        )
        .await;
        debug!(target: "hatch::proxy", server = %reg.server_name, %host, "denied");
        return Ok(());
    }

    let target_addr = format!("{host}:443");
    let upstream = match tokio::net::lookup_host(&target_addr).await {
        Ok(mut iter) => match iter.next() {
            Some(sa) => sa,
            None => {
                warn!(target: "hatch::proxy", %host, "no address");
                return Ok(());
            }
        },
        Err(e) => {
            warn!(target: "hatch::proxy", %host, "resolve: {e}");
            return Ok(());
        }
    };

    let mut up = TcpStream::connect(upstream).await?;
    up.write_all(hello).await?;

    emit(
        &events,
        ProxyEvent::Allowed {
            server: reg.server_name.clone(),
            host: host.clone(),
        },
    )
    .await;

    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = up.split();
    let max = reg.max_bytes_per_connection;
    let counted_max = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let a = pump(&mut cr, &mut uw, max, counted_max.clone());
    let b = pump(&mut ur, &mut cw, max, counted_max.clone());
    let _ = tokio::try_join!(a, b);
    Ok(())
}

async fn pump<R, W>(
    src: &mut R,
    dst: &mut W,
    max_bytes: Option<u64>,
    counter: Arc<std::sync::atomic::AtomicU64>,
) -> std::io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 16384];
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let prev = counter.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        if let Some(limit) = max_bytes {
            if prev + n as u64 > limit {
                debug!(target: "hatch::proxy", "per-conn byte cap reached");
                break;
            }
        }
        dst.write_all(&buf[..n]).await?;
    }
    let _ = dst.flush().await;
    Ok(())
}

async fn emit(events: &Option<EventSink>, ev: ProxyEvent) {
    if let Some(s) = events {
        let _ = s.send(ev).await;
    }
}

pub fn make_event_channel(buf: usize) -> (EventSink, mpsc::Receiver<ProxyEvent>) {
    mpsc::channel(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProxyRegistration;
    use hatch_core::compile::NetworkAllowSet;

    #[tokio::test]
    async fn proxy_starts_and_stops() {
        let registry = ProxyRegistry::new();
        registry
            .register(ProxyRegistration {
                server_id: "id".into(),
                server_name: "test".into(),
                allow: Arc::new(NetworkAllowSet::default()),
                rate_limit_mbps: None,
                max_bytes_per_connection: None,
            })
            .await;
        let srv = ProxyServer {
            listen: "127.0.0.1:0".parse().unwrap(),
            registry,
            events: None,
        };
        let handle = srv.start().await.unwrap();
        let _ = handle.addr;
        handle.shutdown().await;
    }
}
