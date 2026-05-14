# Manifest schema

Manifests are TOML documents that declare a server's required capabilities.
The daemon refuses to spawn a server whose manifest fails validation, and
records its risk score so the user can see how much power the server is
being given.

## Required metadata

```toml
schema_version = "1.0"
name = "github"
version = "1.2.0"
description = "Official GitHub MCP server"
homepage = "https://github.com/modelcontextprotocol/servers"
license = "MIT"
```

`name` must match `^[a-z0-9][a-z0-9-]{0,62}$`. `version` must be valid
semver. The daemon supports the latest two major schema versions.

## Launch command

```toml
[command]
program = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
working_dir = "$HATCH_RUNTIME_DIR"
```

Template variables expanded at launch: `$HOME`, `$HATCH_RUNTIME_DIR`,
`$HATCH_STATE_DIR`, `$PROJECT_ROOT`, `$XDG_CONFIG_HOME`, `$XDG_DATA_HOME`,
`$USER`.

## Integrity verification

```toml
[integrity]
npm_package = "@modelcontextprotocol/server-github"
npm_version = "0.6.2"
npm_integrity = "sha512-..."
```

Pip equivalents: `pip_package`, `pip_version`, `pip_hash`. Git equivalents:
`git_repo`, `git_ref`, `git_commit`.

## Network policy

```toml
[network]
allow_https = ["api.github.com", "*.githubusercontent.com"]
allow_dns   = ["api.github.com", "*.githubusercontent.com"]
allow_http  = false
rate_limit_mbps = 10
max_bytes_per_connection_mb = 100
```

## Filesystem policy

```toml
[filesystem]
read   = []
write  = []
tmpfs  = ["/tmp"]
deny   = []
```

`filesystem.write` paths cannot overlap any of `/`, `/etc`, `/usr`, `/bin`,
`/sbin`, `/boot`, `/sys`, `/proc`. `read = ["$HOME"]` is allowed but adds a
large amount to the risk score and is flagged at install.

## Environment

```toml
[env]
passthrough = ["GITHUB_TOKEN"]
set = { NODE_OPTIONS = "--no-deprecation" }
unset = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
```

## Subprocess policy

```toml
[exec]
allow_subprocess = false
allow_binaries = []
```

`allow_binaries` must be absolute paths.

## Resource limits

```toml
[resources]
memory_mb = 512
cpu_percent = 50
pids_max = 50
nofile = 256
tool_call_timeout_seconds = 60
```

`memory_mb` must be at least 64.

## Tool policy

```toml
[tool_policy]
require_approval = ["delete_*", "force_push", "admin_*"]
deny = ["execute_arbitrary_code"]

[[tool_policy.rules]]
tool = "git.push"
when = "args.branch in ['main', 'master', 'production']"
action = "require_approval"

[[tool_policy.response_filters]]
pattern = "(?i)(api[_-]?key|secret|token)\\s*[:=]\\s*[\\w.-]+"
replacement = "[REDACTED]"
```

`when` is a CEL expression evaluated against the tool call's arguments.

## Platform overrides

```toml
[platform.linux]
seccomp_preset = "strict"   # permissive | default | strict
landlock = true
extra_caps = []

[platform.macos]
endpoint_security = false
extra_sbpl = ""
```

## Signature

```toml
[signature]
key_id = "hatch-registry-2026"
algorithm = "ed25519"
sig = "base64-encoded-64-bytes"
signed_at = "2026-05-01T00:00:00Z"
```

The signed bytes are the canonical JSON serialization of the manifest with
the `[signature]` section removed. See
[`crates/hatch-core/src/sig.rs`](https://github.com/malwarebo/hatch/blob/main/crates/hatch-core/src/sig.rs)
for the exact algorithm.
