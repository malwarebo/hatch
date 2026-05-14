use crate::manifest::{Manifest, SeccompPreset};

#[derive(Debug, Clone, Default)]
pub struct RiskBreakdown {
    pub entries: Vec<(String, i32)>,
}

impl RiskBreakdown {
    pub fn score(&self) -> u32 {
        let total: i32 = self.entries.iter().map(|(_, v)| *v).sum();
        total.max(0) as u32
    }

    pub fn level(&self) -> &'static str {
        match self.score() {
            0..=99 => "low",
            100..=299 => "moderate",
            300..=599 => "high",
            _ => "very_high",
        }
    }

    fn push(&mut self, label: impl Into<String>, delta: i32) {
        if delta != 0 {
            self.entries.push((label.into(), delta));
        }
    }
}

pub fn breakdown(m: &Manifest) -> RiskBreakdown {
    let mut b = RiskBreakdown::default();

    for h in &m.network.allow_https {
        if h.contains('*') {
            b.push(format!("wildcard network: {h}"), 15);
        } else {
            b.push(format!("network: {h}"), 5);
        }
    }
    for h in &m.network.allow_dns {
        if h.contains('*') {
            b.push(format!("wildcard dns: {h}"), 15);
        } else {
            b.push(format!("dns: {h}"), 5);
        }
    }
    if m.network.allow_http {
        b.push("plaintext http allowed", 30);
    }

    for p in &m.filesystem.read {
        if is_broad_path(p) {
            b.push(format!("broad read: {p}"), 100);
        } else {
            b.push(format!("fs read: {p}"), 10);
        }
    }
    for p in &m.filesystem.write {
        if is_broad_path(p) {
            b.push(format!("broad write: {p}"), 100);
        } else {
            b.push(format!("fs write: {p}"), 20);
        }
    }

    if m.exec.allow_subprocess {
        b.push("subprocess allowed", 50);
    }
    for bin in &m.exec.allow_binaries {
        b.push(format!("allowed binary: {bin}"), 5);
    }

    match m.platform.linux.seccomp_preset {
        SeccompPreset::Permissive => b.push("seccomp permissive", 100),
        SeccompPreset::Default => b.push("seccomp default", 30),
        SeccompPreset::Strict => {}
    }

    if cfg!(target_os = "macos") && !m.platform.macos.endpoint_security && m.exec.allow_subprocess {
        b.push("macos subprocess without ES", 200);
    }

    if m.signature.is_none() {
        b.push("unsigned manifest", 500);
    }

    b
}

pub fn is_broad_path(p: &str) -> bool {
    if p.is_empty() {
        return false;
    }
    matches!(
        p,
        "/" | "$HOME" | "$XDG_CONFIG_HOME" | "$XDG_DATA_HOME" | "/home" | "/root" | "/Users"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;

    fn min_manifest_unsigned() -> Manifest {
        let s = include_str!("../tests/fixtures/minimal.toml");
        Manifest::parse_str(s).unwrap()
    }

    #[test]
    fn unsigned_pushes_score() {
        let m = min_manifest_unsigned();
        let b = breakdown(&m);
        assert!(b.entries.iter().any(|(l, _)| l == "unsigned manifest"));
        assert!(b.score() >= 500);
        assert_eq!(b.level(), "high");
    }

    #[test]
    fn wildcard_costs_more_than_specific() {
        let mut m = min_manifest_unsigned();
        m.network.allow_https = vec!["*.example.com".into(), "api.example.com".into()];
        let b = breakdown(&m);
        let wc = b
            .entries
            .iter()
            .find(|(l, _)| l == "wildcard network: *.example.com")
            .unwrap()
            .1;
        let sp = b
            .entries
            .iter()
            .find(|(l, _)| l == "network: api.example.com")
            .unwrap()
            .1;
        assert!(wc > sp);
    }
}
