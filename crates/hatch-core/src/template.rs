use std::collections::HashMap;
use std::path::PathBuf;

use crate::manifest::Manifest;
use crate::CoreError;

#[derive(Debug, Clone)]
pub struct TemplateContext {
    pub vars: HashMap<String, String>,
}

impl TemplateContext {
    pub fn from_env() -> Self {
        let mut vars = HashMap::new();

        if let Some(home) = dirs::home_dir() {
            vars.insert("HOME".into(), home.to_string_lossy().into_owned());
        }
        if let Some(cfg) = dirs::config_dir() {
            vars.insert("XDG_CONFIG_HOME".into(), cfg.to_string_lossy().into_owned());
        }
        if let Some(data) = dirs::data_dir() {
            vars.insert("XDG_DATA_HOME".into(), data.to_string_lossy().into_owned());
        }
        if let Some(state) = dirs::state_dir().or_else(dirs::data_local_dir) {
            vars.insert(
                "XDG_STATE_HOME".into(),
                state.to_string_lossy().into_owned(),
            );
        }
        if let Some(cache) = dirs::cache_dir() {
            vars.insert(
                "XDG_CACHE_HOME".into(),
                cache.to_string_lossy().into_owned(),
            );
        }
        if let Ok(user) = std::env::var("USER") {
            vars.insert("USER".into(), user);
        }
        if let Ok(cwd) = std::env::current_dir() {
            vars.insert("PROJECT_ROOT".into(), cwd.to_string_lossy().into_owned());
        }

        Self { vars }
    }

    pub fn empty() -> Self {
        Self {
            vars: HashMap::new(),
        }
    }

    pub fn with(mut self, key: &str, value: impl Into<String>) -> Self {
        self.vars.insert(key.into(), value.into());
        self
    }

    pub fn set_runtime_dirs(&mut self, runtime: &str, state: &str) {
        self.vars.insert("HATCH_RUNTIME_DIR".into(), runtime.into());
        self.vars.insert("HATCH_STATE_DIR".into(), state.into());
    }

    pub fn resolve(&self, input: &str) -> Result<String, CoreError> {
        let mut out = String::with_capacity(input.len());
        let bytes = input.as_bytes();
        let mut i = 0usize;

        while i < bytes.len() {
            if bytes[i] == b'$' && i + 1 < bytes.len() {
                let (name, consumed) = if bytes[i + 1] == b'{' {
                    let end = match input[i + 2..].find('}') {
                        Some(off) => i + 2 + off,
                        None => return Err(CoreError::UnsetTemplate(input.into())),
                    };
                    (&input[i + 2..end], end - i + 1)
                } else {
                    let rest = &input[i + 1..];
                    let take = rest
                        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                        .unwrap_or(rest.len());
                    (&rest[..take], take + 1)
                };

                if name.is_empty() {
                    out.push('$');
                    i += 1;
                    continue;
                }
                match self.vars.get(name) {
                    Some(v) => out.push_str(v),
                    None => return Err(CoreError::UnsetTemplate(name.into())),
                }
                i += consumed;
            } else {
                out.push(bytes[i] as char);
                i += 1;
            }
        }
        Ok(out)
    }

    pub fn resolve_path(&self, input: &str) -> Result<PathBuf, CoreError> {
        Ok(PathBuf::from(self.resolve(input)?))
    }
}

pub fn resolve_manifest(m: &Manifest, ctx: &TemplateContext) -> Result<Manifest, CoreError> {
    let mut out = m.clone();
    if let Some(wd) = &m.command.working_dir {
        out.command.working_dir = Some(ctx.resolve(wd)?);
    }
    out.command.args = m
        .command
        .args
        .iter()
        .map(|a| ctx.resolve(a))
        .collect::<Result<_, _>>()?;

    out.filesystem.read = resolve_paths(&m.filesystem.read, ctx)?;
    out.filesystem.write = resolve_paths(&m.filesystem.write, ctx)?;
    out.filesystem.tmpfs = resolve_paths(&m.filesystem.tmpfs, ctx)?;
    out.filesystem.deny = resolve_paths(&m.filesystem.deny, ctx)?;

    for (k, v) in &m.env.set {
        out.env.set.insert(k.clone(), ctx.resolve(v)?);
    }

    Ok(out)
}

fn resolve_paths(items: &[String], ctx: &TemplateContext) -> Result<Vec<String>, CoreError> {
    items.iter().map(|p| ctx.resolve(p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_simple_var() {
        let ctx = TemplateContext::empty().with("HOME", "/home/me");
        assert_eq!(ctx.resolve("$HOME/.ssh").unwrap(), "/home/me/.ssh");
        assert_eq!(ctx.resolve("${HOME}/x").unwrap(), "/home/me/x");
    }

    #[test]
    fn errors_on_unset() {
        let ctx = TemplateContext::empty();
        let err = ctx.resolve("$NOPE/x").unwrap_err();
        match err {
            CoreError::UnsetTemplate(n) => assert_eq!(n, "NOPE"),
            other => panic!("wrong: {other:?}"),
        }
    }

    #[test]
    fn dollar_alone_is_literal() {
        let ctx = TemplateContext::empty();
        assert_eq!(ctx.resolve("hello $ world").unwrap(), "hello $ world");
    }
}
