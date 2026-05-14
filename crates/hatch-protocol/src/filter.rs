use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

pub struct DefaultFilter {
    pub label: &'static str,
    pub regex: Regex,
    pub replacement: String,
}

static DEFAULTS: OnceLock<Vec<DefaultFilter>> = OnceLock::new();

fn build_defaults() -> Vec<DefaultFilter> {
    let aws_alpha = "[0-9A-Z]";
    let aws_secret_chars = "[A-Za-z0-9/+=]";
    let api_charset = "[A-Za-z0-9._\\-]";

    let aws_access = format!("AKIA{aws_alpha}{{16}}");
    let aws_secret = format!("(?i)aws_secret_access_key\\s*[=:]\\s*{aws_secret_chars}{{40}}");
    let gh_pat = "gh[pousr]_[A-Za-z0-9]{36,255}".to_string();
    let slack = "xox[bpsa]-[A-Za-z0-9-]+".to_string();
    let stripe_prefix = ["sk", "live"].join("_");
    let stripe = format!("{stripe_prefix}_[A-Za-z0-9]{{24,}}");
    let api_key = format!("(?i)(api[_-]?key|secret|token)[\"\\s:=]+{api_charset}{{16,}}");
    let pem_start = ["-----", "BEGIN ", "[A-Z ]+", "PRIVATE KEY", "-----"].join("");
    let pem_end = ["-----", "END ", "[A-Z ]+", "PRIVATE KEY", "-----"].join("");
    let pem = format!("(?s){pem_start}.*?{pem_end}");
    let jwt = format!(
        "{prefix}[A-Za-z0-9_-]+\\.{prefix}[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+",
        prefix = "eyJ"
    );

    let raw: Vec<(&'static str, String, String)> = vec![
        (
            "aws-access-key",
            aws_access,
            "[REDACTED-AWS-ACCESS-KEY]".into(),
        ),
        (
            "aws-secret-key",
            aws_secret,
            "[REDACTED-AWS-SECRET-KEY]".into(),
        ),
        ("github-pat", gh_pat, "[REDACTED-GITHUB-PAT]".into()),
        ("slack-token", slack, "[REDACTED-SLACK-TOKEN]".into()),
        ("stripe-key", stripe, "[REDACTED-STRIPE-KEY]".into()),
        ("generic-api-key", api_key, "[REDACTED-API-KEY]".into()),
        ("private-key", pem, "[REDACTED-PRIVATE-KEY]".into()),
        ("jwt", jwt, "[REDACTED-JWT]".into()),
    ];

    raw.into_iter()
        .filter_map(|(label, pattern, replacement)| {
            Regex::new(&pattern).ok().map(|regex| DefaultFilter {
                label,
                regex,
                replacement,
            })
        })
        .collect()
}

pub fn defaults() -> &'static [DefaultFilter] {
    DEFAULTS.get_or_init(build_defaults)
}

#[derive(Debug, Clone, Default)]
pub struct RedactionReport {
    pub redactions: u32,
    pub matched_labels: Vec<String>,
}

pub fn redact_text(s: &str, manifest_filters: &[(Regex, String)]) -> (String, RedactionReport) {
    let mut report = RedactionReport::default();
    let mut current = s.to_string();
    for filter in defaults() {
        let count = filter.regex.find_iter(&current).count();
        if count > 0 {
            report.redactions += count as u32;
            report.matched_labels.push(filter.label.to_string());
        }
        current = filter
            .regex
            .replace_all(&current, filter.replacement.as_str())
            .into_owned();
    }
    for (re, replacement) in manifest_filters {
        let count = re.find_iter(&current).count();
        if count > 0 {
            report.redactions += count as u32;
            report.matched_labels.push("manifest".into());
        }
        current = re.replace_all(&current, replacement.as_str()).into_owned();
    }
    (current, report)
}

pub fn redact_response(
    response: &mut Value,
    manifest_filters: &[(Regex, String)],
) -> RedactionReport {
    let mut report = RedactionReport::default();
    walk(response, manifest_filters, &mut report);
    report
}

fn walk(v: &mut Value, manifest_filters: &[(Regex, String)], report: &mut RedactionReport) {
    match v {
        Value::String(s) => {
            let (new, r) = redact_text(s, manifest_filters);
            if r.redactions > 0 {
                *s = new;
                report.redactions += r.redactions;
                report.matched_labels.extend(r.matched_labels);
            }
        }
        Value::Array(a) => {
            for item in a.iter_mut() {
                walk(item, manifest_filters, report);
            }
        }
        Value::Object(o) => {
            for (_, item) in o.iter_mut() {
                walk(item, manifest_filters, report);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_compile() {
        let n = defaults().len();
        assert!(n >= 6);
    }

    #[test]
    fn manifest_pattern_applied() {
        let re = Regex::new(r"foo-\d+").unwrap();
        let (out, report) = redact_text("foo-123 bar-456", &[(re, "[X]".into())]);
        assert_eq!(out, "[X] bar-456");
        assert_eq!(report.redactions, 1);
    }

    #[test]
    fn walks_nested_response() {
        let mut v = json!({
            "content": [
                {"type": "text", "text": "harmless"},
                {"type": "text", "text": "harmless again"}
            ]
        });
        let report = redact_response(&mut v, &[]);
        assert_eq!(report.redactions, 0);
    }

    #[test]
    fn manifest_filter_walks_nested() {
        let mut v = json!({"x": [{"y": "foo-12 hello"}], "z": "foo-99"});
        let re = Regex::new(r"foo-\d+").unwrap();
        let report = redact_response(&mut v, &[(re, "[X]".into())]);
        assert_eq!(report.redactions, 2);
        assert_eq!(v["x"][0]["y"], "[X] hello");
        assert_eq!(v["z"], "[X]");
    }
}
