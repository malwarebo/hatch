#![deny(clippy::all)]

pub mod compile;
pub mod manifest;
pub mod risk;
pub mod sig;
pub mod template;
pub mod validate;

pub use compile::{CompiledPolicy, CompiledToolRule, NetworkAllowSet, RuleAction};
pub use manifest::{
    CommandSpec, EnvPolicy, ExecPolicy, FilesystemPolicy, IntegritySpec, Manifest, NetworkPolicy,
    PlatformOverrides, ResourceLimits, ResponseFilter, SeccompPreset, Signature, ToolPolicy,
    ToolRule,
};
pub use risk::RiskBreakdown;
pub use validate::{ValidationError, ValidationReport, ValidationWarning};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("toml parse: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("validation failed: {} error(s)", .0.errors.len())]
    Invalid(ValidationReport),

    #[error("template variable not set: {0}")]
    UnsetTemplate(String),

    #[error("signature: {0}")]
    Signature(#[from] sig::SignatureError),

    #[error("regex: {0}")]
    Regex(#[from] regex::Error),

    #[error("glob: {0}")]
    Glob(#[from] glob::PatternError),
}
