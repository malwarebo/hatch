use std::sync::Arc;
use std::time::Instant;

use hatch_audit::{AuditWriter, EventBuilder};
use hatch_ipc::DaemonPaths;
use hatch_proxy::ProxyRegistry;
use hatch_state::Store;

use crate::approvals::ApprovalBroker;
use crate::metrics;

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

    pub fn record_audit(&self, ev: EventBuilder) {
        let ty = ev.event_type();
        match self.audit.write(ev) {
            Ok(_) => {
                if let Some(m) = metrics::get() {
                    m.audit_events_total.with_label_values(&[ty.as_str()]).inc();
                }
            }
            Err(e) => {
                tracing::warn!(target: "hatch::audit", event_type = %ty.as_str(), error = %e, "audit write failed");
                if let Some(m) = metrics::get() {
                    m.audit_write_errors_total.inc();
                }
            }
        }
    }
}
