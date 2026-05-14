use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use hatch_audit::{EventBuilder, EventType};
use hatch_core::{validate, Manifest};
use hatch_ipc::{ErrorCode, InstallSource, ManifestSummary};
use hatch_state::ManifestRow;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::state_layer::DaemonState;

pub struct InstallOutcome {
    pub name: String,
    pub version: String,
    pub risk_score: u32,
}

pub fn install(
    state: &DaemonState,
    source: &InstallSource,
    allow_unsigned: bool,
) -> std::result::Result<InstallOutcome, (ErrorCode, String)> {
    let (raw, source_label) = match source {
        InstallSource::File { path } => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| (ErrorCode::Internal, format!("read manifest: {e}")))?;
            (raw, "local")
        }
        InstallSource::Registry { name, version } => {
            let _ = (name, version);
            return Err((
                ErrorCode::Internal,
                "registry install is not implemented in Phase A".into(),
            ));
        }
        InstallSource::Git { url, git_ref } => {
            let _ = (url, git_ref);
            return Err((
                ErrorCode::Internal,
                "git install is not implemented in Phase A".into(),
            ));
        }
    };

    let manifest = Manifest::parse_str(&raw)
        .map_err(|e| (ErrorCode::ManifestInvalid, format!("parse: {e}")))?;
    let report = validate::validate(&manifest);
    if !report.ok() {
        let msg = report
            .errors
            .iter()
            .map(|e| format!("{}: {}", e.field, e.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err((ErrorCode::ManifestInvalid, msg));
    }

    if manifest.signature.is_none() && !allow_unsigned {
        return Err((
            ErrorCode::SignatureFailed,
            "manifest is unsigned; pass --allow-unsigned to override".into(),
        ));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let row = ManifestRow {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        source: source_label.into(),
        signature_verified: manifest.signature.is_some(),
        risk_score: report.risk_score,
        installed_at: now,
        content: raw,
    };
    state
        .store
        .put_manifest(&row)
        .map_err(|e| (ErrorCode::Internal, format!("persist: {e}")))?;

    let _ = state.audit.write(
        EventBuilder::new(EventType::SignatureVerified)
            .server(&manifest.name)
            .field("source", source_label)
            .field("signed", manifest.signature.is_some())
            .field("risk_score", report.risk_score)
            .field("risk_level", report.risk_level.clone()),
    );

    Ok(InstallOutcome {
        name: manifest.name,
        version: manifest.version,
        risk_score: report.risk_score,
    })
}

pub fn list(state: &DaemonState) -> Result<Vec<ManifestSummary>> {
    let rows = state.store.list_manifests().context("list manifests")?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let installed_at = OffsetDateTime::from_unix_timestamp(r.installed_at)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH)
            .format(&Rfc3339)
            .unwrap_or_default();
        out.push(ManifestSummary {
            name: r.name,
            version: r.version,
            source: r.source,
            signature_verified: r.signature_verified,
            risk_score: r.risk_score,
            installed_at,
        });
    }
    Ok(out)
}

pub fn uninstall(state: &DaemonState, name: &str) -> Result<usize> {
    let removed = state
        .store
        .delete_manifest(name)
        .map_err(|e| anyhow!("delete manifest: {e}"))?;
    if removed == 0 {
        return Err(anyhow!("no manifest named {name}"));
    }
    let _ = state.audit.write(
        EventBuilder::new(EventType::ConfigSync)
            .server(name)
            .field("op", "uninstall"),
    );
    Ok(removed)
}

pub fn fetch(state: &DaemonState, name: &str) -> Result<Manifest> {
    let row = state
        .store
        .get_manifest_latest(name)
        .context("read manifest")?
        .ok_or_else(|| anyhow!("manifest {name} is not installed"))?;
    Manifest::parse_str(&row.content).map_err(|e| anyhow!("re-parse manifest: {e}"))
}
