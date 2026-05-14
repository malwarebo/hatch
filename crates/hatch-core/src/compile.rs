use std::collections::BTreeMap;
use std::path::PathBuf;

use regex::Regex;

use crate::manifest::{Manifest, ResponseFilter, RuleActionStr};
use crate::template::TemplateContext;
use crate::validate::ValidationReport;
use crate::{validate, CoreError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
    RequireApproval,
}

impl From<RuleActionStr> for RuleAction {
    fn from(s: RuleActionStr) -> Self {
        match s {
            RuleActionStr::Allow => RuleAction::Allow,
            RuleActionStr::Deny => RuleAction::Deny,
            RuleActionStr::RequireApproval => RuleAction::RequireApproval,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledToolRule {
    pub tool_pattern: glob::Pattern,
    pub when: Option<String>,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkAllowSet {
    pub https_exact: Vec<String>,
    pub https_suffix: Vec<String>,
    pub dns_exact: Vec<String>,
    pub dns_suffix: Vec<String>,
    pub allow_http: bool,
}

impl NetworkAllowSet {
    pub fn from_lists(https: &[String], dns: &[String], allow_http: bool) -> Self {
        let mut out = NetworkAllowSet {
            allow_http,
            ..Default::default()
        };
        for h in https {
            if let Some(rest) = h.strip_prefix("*.") {
                out.https_suffix.push(rest.to_string());
            } else {
                out.https_exact.push(h.clone());
            }
        }
        for h in dns {
            if let Some(rest) = h.strip_prefix("*.") {
                out.dns_suffix.push(rest.to_string());
            } else {
                out.dns_exact.push(h.clone());
            }
        }
        out
    }

    pub fn https_allows(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        if self
            .https_exact
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
        {
            return true;
        }
        self.https_suffix.iter().any(|suf| {
            host.len() > suf.len() + 1
                && host.ends_with(suf)
                && host.as_bytes()[host.len() - suf.len() - 1] == b'.'
        })
    }

    pub fn dns_allows(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        if self.dns_exact.iter().any(|h| h.eq_ignore_ascii_case(host)) {
            return true;
        }
        self.dns_suffix.iter().any(|suf| {
            host.len() > suf.len() + 1
                && host.ends_with(suf)
                && host.as_bytes()[host.len() - suf.len() - 1] == b'.'
        })
    }
}

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub manifest: Manifest,
    pub resolved_paths_read: Vec<PathBuf>,
    pub resolved_paths_write: Vec<PathBuf>,
    pub resolved_env: BTreeMap<String, String>,
    pub network_allow: NetworkAllowSet,
    pub tool_rules: Vec<CompiledToolRule>,
    pub response_filters: Vec<(Regex, String)>,
    pub risk_score: u32,
    pub validation: ValidationReport,
}

pub fn compile(m: &Manifest, ctx: &TemplateContext) -> Result<CompiledPolicy, CoreError> {
    let report = validate::validate(m);
    if !report.ok() {
        return Err(CoreError::Invalid(report));
    }
    let resolved = crate::template::resolve_manifest(m, ctx)?;

    let resolved_paths_read = resolved.filesystem.read.iter().map(PathBuf::from).collect();
    let resolved_paths_write = resolved
        .filesystem
        .write
        .iter()
        .map(PathBuf::from)
        .collect();

    let resolved_env = resolved.env.set.clone();

    let network_allow = NetworkAllowSet::from_lists(
        &resolved.network.allow_https,
        &resolved.network.allow_dns,
        resolved.network.allow_http,
    );

    let mut tool_rules = Vec::with_capacity(resolved.tool_policy.rules.len());
    for r in &resolved.tool_policy.rules {
        tool_rules.push(CompiledToolRule {
            tool_pattern: glob::Pattern::new(&r.tool)?,
            when: r.when.clone(),
            action: r.action.into(),
        });
    }

    let mut response_filters = Vec::with_capacity(resolved.tool_policy.response_filters.len());
    for ResponseFilter {
        pattern,
        replacement,
    } in &resolved.tool_policy.response_filters
    {
        response_filters.push((Regex::new(pattern)?, replacement.clone()));
    }

    Ok(CompiledPolicy {
        manifest: resolved,
        resolved_paths_read,
        resolved_paths_write,
        resolved_env,
        network_allow,
        tool_rules,
        response_filters,
        risk_score: report.risk_score,
        validation: report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;

    const MIN: &str = include_str!("../tests/fixtures/minimal.toml");

    #[test]
    fn compiles_minimal() {
        let m = Manifest::parse_str(MIN).unwrap();
        let ctx = TemplateContext::empty().with("HOME", "/home/me");
        let p = compile(&m, &ctx).unwrap();
        assert_eq!(p.manifest.name, "example");
        assert!(p.tool_rules.is_empty());
        assert!(p.response_filters.is_empty());
    }

    #[test]
    fn rejects_invalid_manifest() {
        let mut m = Manifest::parse_str(MIN).unwrap();
        m.name = "Bad Name".into();
        let ctx = TemplateContext::empty();
        let err = compile(&m, &ctx).unwrap_err();
        match err {
            CoreError::Invalid(report) => assert!(!report.ok()),
            other => panic!("wrong: {other:?}"),
        }
    }

    #[test]
    fn network_allow_set_suffix_matching() {
        let s = NetworkAllowSet::from_lists(
            &["api.example.com".into(), "*.example.com".into()],
            &[],
            false,
        );
        assert!(s.https_allows("api.example.com"));
        assert!(s.https_allows("foo.example.com"));
        assert!(!s.https_allows("example.com"));
        assert!(!s.https_allows("evil.com"));
        assert!(!s.https_allows("foo.bar.example.com.evil.com"));
    }
}
