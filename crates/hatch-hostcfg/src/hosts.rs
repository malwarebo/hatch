use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostKind {
    ClaudeDesktop,
    Cursor,
    ClaudeCode,
    Zed,
    Continue,
    Windsurf,
}

impl HostKind {
    pub fn all() -> &'static [HostKind] {
        &[
            HostKind::ClaudeDesktop,
            HostKind::Cursor,
            HostKind::ClaudeCode,
            HostKind::Zed,
            HostKind::Continue,
            HostKind::Windsurf,
        ]
    }

    pub fn slug(self) -> &'static str {
        match self {
            HostKind::ClaudeDesktop => "claude-desktop",
            HostKind::Cursor => "cursor",
            HostKind::ClaudeCode => "claude-code",
            HostKind::Zed => "zed",
            HostKind::Continue => "continue",
            HostKind::Windsurf => "windsurf",
        }
    }

    pub fn config_field(self) -> &'static str {
        match self {
            HostKind::ClaudeDesktop
            | HostKind::ClaudeCode
            | HostKind::Cursor
            | HostKind::Continue
            | HostKind::Windsurf => "mcpServers",
            HostKind::Zed => "context_servers",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HostSpec {
    pub kind: HostKind,
    pub path: PathBuf,
}

impl HostSpec {
    pub fn discover(kind: HostKind, home: Option<&std::path::Path>) -> Option<Self> {
        let home = home.map(|p| p.to_path_buf()).or_else(dirs::home_dir)?;
        let path = match kind {
            HostKind::ClaudeDesktop => {
                if cfg!(target_os = "macos") {
                    home.join("Library/Application Support/Claude/claude_desktop_config.json")
                } else {
                    home.join(".config/Claude/claude_desktop_config.json")
                }
            }
            HostKind::Cursor => home.join(".cursor/mcp.json"),
            HostKind::ClaudeCode => home.join(".claude/settings.json"),
            HostKind::Zed => home.join(".config/zed/settings.json"),
            HostKind::Continue => home.join(".continue/config.json"),
            HostKind::Windsurf => home.join(".codeium/windsurf/mcp_config.json"),
        };
        Some(HostSpec { kind, path })
    }

    pub fn all_known(home: Option<&std::path::Path>) -> Vec<HostSpec> {
        HostKind::all()
            .iter()
            .filter_map(|k| HostSpec::discover(*k, home))
            .collect()
    }
}
