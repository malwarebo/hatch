use std::time::{Duration, Instant};

use hatch_core::compile::{CompiledPolicy, CompiledToolRule, RuleAction};
use serde_json::Value;

use crate::cel::{Context, Program};

#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Deny { reason: String },
    RequireApproval { reason: String },
}

#[derive(Debug, Clone)]
pub struct EvalReport {
    pub decision: Decision,
    pub matched_rule: Option<usize>,
    pub matched_by_glob: bool,
    pub elapsed_ms: u64,
}

pub const EVAL_TIMEOUT: Duration = Duration::from_millis(50);

pub fn evaluate(
    policy: &CompiledPolicy,
    tool: &str,
    args: &Value,
    server: &str,
    caller: &str,
) -> EvalReport {
    let start = Instant::now();

    for pattern in &policy.manifest.tool_policy.deny {
        if glob_match(pattern, tool) {
            return done(
                start,
                Decision::Deny {
                    reason: format!("matched tool_policy.deny pattern {pattern:?}"),
                },
                None,
                true,
            );
        }
    }

    for pattern in &policy.manifest.tool_policy.require_approval {
        if glob_match(pattern, tool) {
            return done(
                start,
                Decision::RequireApproval {
                    reason: format!("matched tool_policy.require_approval pattern {pattern:?}"),
                },
                None,
                true,
            );
        }
    }

    for (idx, rule) in policy.tool_rules.iter().enumerate() {
        if !rule.tool_pattern.matches(tool) {
            continue;
        }
        if rule_matches(rule, tool, args, server, caller) {
            let dec = match rule.action {
                RuleAction::Allow => Decision::Allow,
                RuleAction::Deny => Decision::Deny {
                    reason: format!("matched rule #{idx}"),
                },
                RuleAction::RequireApproval => Decision::RequireApproval {
                    reason: format!("matched rule #{idx}"),
                },
            };
            return done(start, dec, Some(idx), false);
        }
    }

    done(start, Decision::Allow, None, false)
}

fn rule_matches(
    rule: &CompiledToolRule,
    tool: &str,
    args: &Value,
    server: &str,
    caller: &str,
) -> bool {
    let Some(when) = rule.when.as_ref() else {
        return true;
    };
    let prog = match Program::compile(when) {
        Ok(p) => p,
        Err(_) => return true,
    };
    let ctx = Context::with_tool_call(tool, args, server, caller);
    let started = Instant::now();
    let result = prog.run_bool(&ctx);
    if started.elapsed() > EVAL_TIMEOUT {
        return false;
    }
    result.unwrap_or(false)
}

fn glob_match(pattern: &str, tool: &str) -> bool {
    glob::Pattern::new(pattern)
        .map(|p| p.matches(tool))
        .unwrap_or(false)
}

fn done(start: Instant, decision: Decision, idx: Option<usize>, by_glob: bool) -> EvalReport {
    EvalReport {
        decision,
        matched_rule: idx,
        matched_by_glob: by_glob,
        elapsed_ms: start.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hatch_core::{compile::compile, manifest::Manifest, template::TemplateContext};
    use serde_json::json;

    const MIN: &str = include_str!("../../hatch-core/tests/fixtures/minimal.toml");

    fn policy_with_rule(when: &str, action: &str) -> CompiledPolicy {
        let mut m = Manifest::parse_str(MIN).unwrap();
        m.tool_policy.rules.push(hatch_core::manifest::ToolRule {
            tool: "filesystem.write".into(),
            when: Some(when.into()),
            action: serde_json::from_str(&format!("\"{action}\"")).unwrap(),
        });
        compile(&m, &TemplateContext::empty()).unwrap()
    }

    #[test]
    fn allow_by_default() {
        let p = compile(
            &Manifest::parse_str(MIN).unwrap(),
            &TemplateContext::empty(),
        )
        .unwrap();
        let r = evaluate(
            &p,
            "filesystem.read",
            &json!({"path": "/tmp/x"}),
            "fs",
            "cli",
        );
        assert!(matches!(r.decision, Decision::Allow));
    }

    #[test]
    fn deny_by_glob() {
        let mut m = Manifest::parse_str(MIN).unwrap();
        m.tool_policy.deny.push("delete_*".into());
        let p = compile(&m, &TemplateContext::empty()).unwrap();
        let r = evaluate(&p, "delete_everything", &json!({}), "fs", "cli");
        assert!(matches!(r.decision, Decision::Deny { .. }));
    }

    #[test]
    fn require_approval_by_cel() {
        let p = policy_with_rule("args.path.startsWith('/etc/')", "require_approval");
        let r = evaluate(
            &p,
            "filesystem.write",
            &json!({"path": "/etc/passwd"}),
            "fs",
            "cli",
        );
        assert!(matches!(r.decision, Decision::RequireApproval { .. }));
    }
}
