use std::path::Path;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::manifest::{Manifest, RuleActionStr};
use crate::risk;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationWarning {
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidationReport {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
    pub risk_score: u32,
    pub risk_level: String,
}

impl ValidationReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

const FORBIDDEN_WRITE_ANCESTORS: &[&str] = &[
    "/", "/etc", "/usr", "/bin", "/sbin", "/boot", "/sys", "/proc",
];

pub fn validate(m: &Manifest) -> ValidationReport {
    let mut r = ValidationReport::default();

    if m.schema_version != "1.0" {
        r.errors.push(ValidationError {
            field: "schema_version".into(),
            message: format!(
                "unsupported schema version {:?}; expected \"1.0\"",
                m.schema_version
            ),
        });
    }

    let name_re = Regex::new(r"^[a-z0-9][a-z0-9-]{0,62}$").expect("compile name regex");
    if !name_re.is_match(&m.name) {
        r.errors.push(ValidationError {
            field: "name".into(),
            message: format!(
                "{:?} is not a valid name (lowercase alphanumeric + hyphen, 1-63 chars, must start with [a-z0-9])",
                m.name
            ),
        });
    }

    if !is_semver(&m.version) {
        r.errors.push(ValidationError {
            field: "version".into(),
            message: format!("{:?} is not a valid semver", m.version),
        });
    }

    if m.command.program.is_empty() {
        r.errors.push(ValidationError {
            field: "command.program".into(),
            message: "must not be empty".into(),
        });
    }

    for w in &m.filesystem.write {
        for forbidden in FORBIDDEN_WRITE_ANCESTORS {
            if paths_overlap(w, forbidden) {
                r.errors.push(ValidationError {
                    field: "filesystem.write".into(),
                    message: format!("{w:?} overlaps system path {forbidden:?}"),
                });
            }
        }
    }

    for path in &m.filesystem.read {
        if risk::is_broad_path(path) {
            r.warnings.push(ValidationWarning {
                field: "filesystem.read".into(),
                message: format!("{path:?} is very broad; consider narrowing"),
            });
        }
        if path.contains(".ssh") || path.contains(".aws") || path.contains(".gnupg") {
            r.warnings.push(ValidationWarning {
                field: "filesystem.read".into(),
                message: format!("{path:?} points at credential storage"),
            });
        }
    }

    for bin in &m.exec.allow_binaries {
        if !Path::new(bin).is_absolute() {
            r.errors.push(ValidationError {
                field: "exec.allow_binaries".into(),
                message: format!("{bin:?} must be an absolute path"),
            });
        }
    }

    if m.network.allow_http {
        r.warnings.push(ValidationWarning {
            field: "network.allow_http".into(),
            message: "plaintext HTTP allowed; this should be justified in the manifest comment"
                .into(),
        });
    }

    if m.resources.memory_mb < 64 {
        r.errors.push(ValidationError {
            field: "resources.memory_mb".into(),
            message: format!("must be >= 64 MB (got {})", m.resources.memory_mb),
        });
    }
    if m.resources.cpu_percent == 0 || m.resources.cpu_percent > 100 {
        r.errors.push(ValidationError {
            field: "resources.cpu_percent".into(),
            message: format!("must be in 1..=100 (got {})", m.resources.cpu_percent),
        });
    }
    if m.resources.pids_max == 0 {
        r.errors.push(ValidationError {
            field: "resources.pids_max".into(),
            message: "must be >= 1".into(),
        });
    }

    for f in &m.tool_policy.response_filters {
        if let Err(e) = Regex::new(&f.pattern) {
            r.errors.push(ValidationError {
                field: "tool_policy.response_filters.pattern".into(),
                message: format!("regex {:?} failed to compile: {e}", f.pattern),
            });
        }
    }

    for (i, rule) in m.tool_policy.rules.iter().enumerate() {
        if rule.tool.is_empty() {
            r.errors.push(ValidationError {
                field: format!("tool_policy.rules[{i}].tool"),
                message: "must not be empty".into(),
            });
        }
        if let Err(e) = glob::Pattern::new(&rule.tool) {
            r.errors.push(ValidationError {
                field: format!("tool_policy.rules[{i}].tool"),
                message: format!("invalid glob {:?}: {e}", rule.tool),
            });
        }
        match rule.action {
            RuleActionStr::Allow | RuleActionStr::Deny | RuleActionStr::RequireApproval => {}
        }
    }

    let network_empty = m.network.allow_https.is_empty()
        && m.network.allow_dns.is_empty()
        && !m.exec.allow_subprocess;
    if network_empty && m.filesystem.read.is_empty() && m.filesystem.write.is_empty() {
        r.warnings.push(ValidationWarning {
            field: "policy".into(),
            message: "manifest grants no capabilities; verify this is intended".into(),
        });
    }

    let breakdown = risk::breakdown(m);
    r.risk_score = breakdown.score();
    r.risk_level = breakdown.level().to_string();

    r
}

fn paths_overlap(a: &str, b: &str) -> bool {
    let a = normalize(a);
    let b = normalize(b);
    if a == b {
        return true;
    }
    is_strict_ancestor(&a, &b) || is_strict_ancestor(&b, &a)
}

fn is_strict_ancestor(parent: &str, child: &str) -> bool {
    if parent == "/" {
        return child.starts_with('/') && child != "/";
    }
    let prefix = format!("{parent}/");
    child.starts_with(&prefix)
}

fn normalize(p: &str) -> String {
    if p.is_empty() {
        return "/".into();
    }
    let mut s = p.replace("//", "/");
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    s
}

fn is_semver(v: &str) -> bool {
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;

    const MIN: &str = include_str!("../tests/fixtures/minimal.toml");

    #[test]
    fn minimal_is_valid() {
        let m = Manifest::parse_str(MIN).unwrap();
        let r = validate(&m);
        assert!(r.ok(), "errors: {:?}", r.errors);
    }

    #[test]
    fn bad_name_rejected() {
        let mut m = Manifest::parse_str(MIN).unwrap();
        m.name = "Has_Caps".into();
        let r = validate(&m);
        assert!(!r.ok());
        assert!(r.errors.iter().any(|e| e.field == "name"));
    }

    #[test]
    fn rejects_etc_write() {
        let mut m = Manifest::parse_str(MIN).unwrap();
        m.filesystem.write = vec!["/etc/passwd".into()];
        let r = validate(&m);
        assert!(!r.ok());
        assert!(r.errors.iter().any(|e| e.field == "filesystem.write"));
    }

    #[test]
    fn rejects_root_write() {
        let mut m = Manifest::parse_str(MIN).unwrap();
        m.filesystem.write = vec!["/".into()];
        let r = validate(&m);
        assert!(!r.ok());
    }

    #[test]
    fn warns_on_home_read() {
        let mut m = Manifest::parse_str(MIN).unwrap();
        m.filesystem.read = vec!["$HOME".into()];
        let r = validate(&m);
        assert!(r.ok());
        assert!(r
            .warnings
            .iter()
            .any(|w| w.field == "filesystem.read" && w.message.contains("very broad")));
    }

    #[test]
    fn risk_score_set() {
        let m = Manifest::parse_str(MIN).unwrap();
        let r = validate(&m);
        assert!(r.risk_score >= 500);
        assert_eq!(r.risk_level, "high");
    }

    #[test]
    fn rejects_bad_semver() {
        let mut m = Manifest::parse_str(MIN).unwrap();
        m.version = "not-a-version".into();
        let r = validate(&m);
        assert!(!r.ok());
    }

    #[test]
    fn rejects_bad_regex() {
        let mut m = Manifest::parse_str(MIN).unwrap();
        m.tool_policy
            .response_filters
            .push(crate::manifest::ResponseFilter {
                pattern: "(unclosed".into(),
                replacement: "X".into(),
            });
        let r = validate(&m);
        assert!(!r.ok());
    }
}
