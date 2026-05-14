use std::net::SocketAddr;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::sni::host_matches;
use crate::ProxyRegistry;

const MAX_TTL: u32 = 300;
const MAX_DNS_PAYLOAD: usize = 4096;

pub struct DnsResolver {
    upstream: Arc<TokioAsyncResolver>,
    registry: ProxyRegistry,
}

impl DnsResolver {
    pub fn new(registry: ProxyRegistry) -> Self {
        let upstream =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Self {
            upstream: Arc::new(upstream),
            registry,
        }
    }

    pub async fn handle(&self, query_bytes: &[u8]) -> Vec<u8> {
        let request = match Message::from_vec(query_bytes) {
            Ok(m) => m,
            Err(e) => {
                debug!(target: "hatch::dns", "parse: {e}");
                return error_response(query_bytes, ResponseCode::FormErr);
            }
        };
        let id = request.id();
        let query = match request.queries().first().cloned() {
            Some(q) => q,
            None => return error_response(query_bytes, ResponseCode::FormErr),
        };
        let name = query.name().to_string();
        let trimmed = name.trim_end_matches('.').to_ascii_lowercase();
        let qtype = query.query_type();

        let reg = match self.registry.lookup_first().await {
            Some(r) => r,
            None => return build_empty(id, &query, ResponseCode::Refused),
        };
        let allow = &reg.allow;
        if !host_matches(&allow.dns_exact, &allow.dns_suffix, &trimmed) {
            return build_empty(id, &query, ResponseCode::NXDomain);
        }
        if !matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::CNAME) {
            return build_empty(id, &query, ResponseCode::Refused);
        }

        let name_obj = match Name::from_utf8(&name) {
            Ok(n) => n,
            Err(_) => return build_empty(id, &query, ResponseCode::FormErr),
        };

        let lookup = match self.upstream.lookup(name_obj.clone(), qtype).await {
            Ok(l) => l,
            Err(e) => {
                debug!(target: "hatch::dns", host = %trimmed, "upstream: {e}");
                return build_empty(id, &query, ResponseCode::ServFail);
            }
        };

        let mut response = Message::new();
        response.set_id(id);
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_recursion_available(true);
        response.set_recursion_desired(request.recursion_desired());
        response.set_response_code(ResponseCode::NoError);
        response.add_query(query.clone());
        for rec in lookup.record_iter() {
            let mut owned = rec.clone();
            if owned.ttl() > MAX_TTL {
                owned.set_ttl(MAX_TTL);
            }
            response.add_answer(owned);
        }
        let _ = request;
        response
            .to_vec()
            .unwrap_or_else(|_| build_empty(id, &query, ResponseCode::ServFail))
    }
}

fn build_empty(id: u16, query: &hickory_proto::op::Query, code: ResponseCode) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_op_code(OpCode::Query);
    msg.set_response_code(code);
    msg.add_query(query.clone());
    msg.to_vec().unwrap_or_default()
}

fn error_response(query: &[u8], code: ResponseCode) -> Vec<u8> {
    let id = if query.len() >= 2 {
        u16::from_be_bytes([query[0], query[1]])
    } else {
        0
    };
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_response_code(code);
    msg.to_vec().unwrap_or_default()
}

pub struct DnsResolverHandle {
    pub addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl DnsResolverHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}

pub async fn start_dns_server(
    bind: SocketAddr,
    registry: ProxyRegistry,
) -> std::io::Result<DnsResolverHandle> {
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    let addr = socket.local_addr()?;
    let resolver = Arc::new(DnsResolver::new(registry));
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
    info!(target: "hatch::dns", %addr, "DNS resolver listening");
    let socket_for_loop = socket.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; MAX_DNS_PAYLOAD];
        loop {
            tokio::select! {
                _ = &mut rx => {
                    info!(target: "hatch::dns", "shutting down");
                    return;
                }
                res = socket_for_loop.recv_from(&mut buf) => {
                    match res {
                        Ok((n, peer)) => {
                            let payload = buf[..n].to_vec();
                            let resolver = resolver.clone();
                            let socket_for_reply = socket_for_loop.clone();
                            tokio::spawn(async move {
                                let response = resolver.handle(&payload).await;
                                if let Err(e) = socket_for_reply.send_to(&response, peer).await {
                                    debug!(target: "hatch::dns", "send: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            warn!(target: "hatch::dns", "recv: {e}");
                        }
                    }
                }
            }
        }
    });
    Ok(DnsResolverHandle { addr, shutdown: tx })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hatch_core::compile::NetworkAllowSet;
    use hickory_proto::op::Query;
    use hickory_proto::rr::DNSClass;

    fn build_query(host: &str, qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(0x1234);
        msg.set_op_code(OpCode::Query);
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(true);
        let name = Name::from_utf8(host).unwrap();
        let mut q = Query::new();
        q.set_name(name);
        q.set_query_class(DNSClass::IN);
        q.set_query_type(qtype);
        msg.add_query(q);
        msg.to_vec().unwrap()
    }

    #[tokio::test]
    async fn rejects_when_no_registration() {
        let registry = ProxyRegistry::new();
        let resolver = DnsResolver::new(registry);
        let q = build_query("api.example.com", RecordType::A);
        let r = resolver.handle(&q).await;
        let msg = Message::from_vec(&r).unwrap();
        assert_eq!(msg.response_code(), ResponseCode::Refused);
    }

    #[tokio::test]
    async fn nxdomain_for_unlisted() {
        let registry = ProxyRegistry::new();
        registry
            .register(crate::ProxyRegistration {
                server_id: "x".into(),
                server_name: "x".into(),
                allow: Arc::new(NetworkAllowSet {
                    dns_exact: vec!["api.allowed.com".into()],
                    ..Default::default()
                }),
                rate_limit_mbps: None,
                max_bytes_per_connection: None,
            })
            .await;
        let resolver = DnsResolver::new(registry);
        let q = build_query("api.other.com", RecordType::A);
        let r = resolver.handle(&q).await;
        let msg = Message::from_vec(&r).unwrap();
        assert_eq!(msg.response_code(), ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn refuses_uncommon_types() {
        let registry = ProxyRegistry::new();
        registry
            .register(crate::ProxyRegistration {
                server_id: "x".into(),
                server_name: "x".into(),
                allow: Arc::new(NetworkAllowSet {
                    dns_exact: vec!["api.allowed.com".into()],
                    ..Default::default()
                }),
                rate_limit_mbps: None,
                max_bytes_per_connection: None,
            })
            .await;
        let resolver = DnsResolver::new(registry);
        let q = build_query("api.allowed.com", RecordType::TXT);
        let r = resolver.handle(&q).await;
        let msg = Message::from_vec(&r).unwrap();
        assert_eq!(msg.response_code(), ResponseCode::Refused);
    }
}
