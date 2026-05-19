#![deny(clippy::all)]

pub mod dns;
pub mod proxy;
pub mod sni;

pub use dns::{DnsResolver, DnsResolverHandle};
pub use proxy::{make_event_channel, ProxyServer, ProxyServerHandle};
pub use sni::{extract_sni, host_matches, SniError};

use std::net::SocketAddr;
use std::sync::Arc;

use hatch_core::compile::NetworkAllowSet;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct ProxyRegistration {
    pub server_id: String,
    pub server_name: String,
    pub allow: Arc<NetworkAllowSet>,
    pub rate_limit_mbps: Option<u32>,
    pub max_bytes_per_connection: Option<u64>,
}

#[derive(Default, Clone)]
pub struct ProxyRegistry {
    inner: Arc<RwLock<Vec<ProxyRegistration>>>,
}

impl ProxyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(&self, reg: ProxyRegistration) {
        self.inner.write().await.push(reg);
    }

    pub async fn deregister(&self, server_id: &str) {
        self.inner
            .write()
            .await
            .retain(|r| r.server_id != server_id);
    }

    pub async fn lookup_by_socket(&self, peer: SocketAddr) -> Option<ProxyRegistration> {
        let _ = peer;
        let r = self.inner.read().await;
        r.first().cloned()
    }

    pub async fn lookup_first(&self) -> Option<ProxyRegistration> {
        self.inner.read().await.first().cloned()
    }
}

#[derive(Debug, Clone)]
pub enum ProxyEvent {
    Allowed {
        server: String,
        host: String,
    },
    Denied {
        server: String,
        host: String,
        reason: String,
    },
}

pub type EventSink = tokio::sync::mpsc::Sender<ProxyEvent>;
