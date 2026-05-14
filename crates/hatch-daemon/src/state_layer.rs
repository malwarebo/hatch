use std::sync::Arc;
use std::time::Instant;

use hatch_audit::AuditWriter;
use hatch_ipc::DaemonPaths;
use hatch_proxy::ProxyRegistry;
use hatch_state::Store;

use crate::approvals::ApprovalBroker;

pub struct DaemonState {
    pub paths: DaemonPaths,
    pub store: Store,
    pub audit: Arc<AuditWriter>,
    pub started_at: Instant,
    pub broker: ApprovalBroker,
    pub proxy_registry: ProxyRegistry,
    pub real_sandbox: bool,
    pub proxy_port: u16,
    pub dns_port: u16,
}

pub struct DaemonStateInit {
    pub paths: DaemonPaths,
    pub store: Store,
    pub audit: AuditWriter,
    pub broker: ApprovalBroker,
    pub proxy_registry: ProxyRegistry,
    pub real_sandbox: bool,
    pub proxy_port: u16,
    pub dns_port: u16,
}

impl DaemonState {
    pub fn new(init: DaemonStateInit) -> Self {
        Self {
            paths: init.paths,
            store: init.store,
            audit: Arc::new(init.audit),
            started_at: Instant::now(),
            broker: init.broker,
            proxy_registry: init.proxy_registry,
            real_sandbox: init.real_sandbox,
            proxy_port: init.proxy_port,
            dns_port: init.dns_port,
        }
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}
