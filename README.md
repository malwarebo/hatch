<div align="center">

<img src="docs/logo.svg" alt="hatch" width="340">

</div>

Capability-based isolation for AI tool servers.

`hatch` sandboxes MCP (Model Context Protocol) servers on Linux and macOS,
enforcing per-server network, filesystem, and protocol-level policies declared
in signed manifests.

It runs as a user-level background daemon (`hatch-daemon`, managed by systemd
on Linux or `launchd` on macOS); per-server `hatch-shim` processes bridge each
MCP host (Claude Desktop, Cursor, Claude Code, Zed, Continue, Windsurf) to the
sandboxed servers the daemon spawns and polices.

The threat model is in [`docs/src/concepts/threat-model.md`](docs/src/concepts/threat-model.md).

## Architecture

```mermaid
%%{init: {"flowchart": {"defaultRenderer": "elk"}}}%%
flowchart LR
    Host[MCP host]

    subgraph trusted [trusted]
        direction TB
        Shim[hatch-shim]
        Daemon[hatch-daemon]
        Enforce["Per-process enforcement<br/>Linux: hatch-linux-helper<br/>Landlock + seccomp<br/>macOS: sandbox-exec"]
        Proxy["SNI proxy<br/>+ DNS allowlist"]
    end

    subgraph sandbox [sandbox]
        Srv[MCP server, untrusted]
    end

    Net[Allowlisted hosts only]

    Host -->|stdio| Shim
    Shim -->|policy query| Daemon
    Daemon -->|decision| Shim
    Daemon -->|spawn| Enforce
    Enforce -->|exec| Srv
    Srv -->|stdio| Shim
    Srv -->|HTTPS| Proxy
    Srv -->|DNS| Proxy
    Proxy -->|verified SNI| Net
```

Sandbox enforcement on Linux: user/mount/pid/net namespaces, cgroups v2,
iptables redirects inside a per-server netns, and a pre-exec helper
(`hatch-linux-helper`) that applies Landlock and seccomp before handing off
to the manifest's program. On macOS: `sandbox-exec` profile, PF anchor per
sandbox UID, and a UID pool.

Every tool call from the host passes through the shim, which queries the
daemon's compiled policy (deny lists, glob patterns, CEL rules over arguments,
response-redaction filters). Every network connection from the sandboxed
server is forced through the SNI proxy and DNS resolver, both of which only
permit destinations declared in the server's signed manifest. Everything is
audited to JSONL with a hash chain.

## Build

```bash
cargo build --release --workspace
cargo test --workspace
```

Release binaries land in `target/release/`: `hatch`, `hatch-daemon`,
`hatch-shim`, and (on Linux) `hatch-linux-helper`.

Requirements: Rust stable (1.83+).

- On Linux: a kernel with user namespaces, cgroups v2, seccomp, and Landlock (5.13+).
- On macOS: 13 or newer.

> Note: there is no Windows support yet.

### Packages

The release workflow (`.github/workflows/release.yml`, triggered by a
`vX.Y.Z` tag) builds `.deb` / `.rpm` / tarball / macOS artifacts and signs each
with [minisign](https://jedisct1.github.io/minisign/) when `MINISIGN_KEY` is
configured. To build packages locally:

```bash
cargo install cargo-deb cargo-generate-rpm
cargo build --release
cargo deb -p hatch-cli --no-build --no-strip   # -> target/debian/hatch_*.deb
(cd crates/hatch-cli && cargo generate-rpm)    # -> target/generate-rpm/hatch-*.rpm
```

`cargo generate-rpm` doesn't resolve nested workspace members via `-p`, so
run it from inside `crates/hatch-cli/`. The macOS signed `.pkg` is produced by
`scripts/notarize-macos.sh <version>` with `APPLE_DEVELOPER_ID_APPLICATION`,
`APPLE_DEVELOPER_ID_INSTALLER`, and `APPLE_NOTARY_PROFILE` set.

The Linux systemd user unit
([`packaging/systemd/hatch-daemon.service`](packaging/systemd/hatch-daemon.service))
is installed by the `.deb`/`.rpm`; enable it with:

```bash
systemctl --user daemon-reload
systemctl --user enable --now hatch-daemon
```

## Run

Smoke-test the full pipeline with no external dependencies. `minimal.toml`
runs `/bin/cat` under the daemon, exercises stdio routing, audit logging,
and the IPC protocol end to end:

```bash
cargo run -p hatch-daemon -- --foreground --state-dir ./.hatch &
cargo run -p hatch-cli   -- --state-dir ./.hatch status
cargo run -p hatch-cli   -- manifest validate examples/manifests/minimal.toml
cargo run -p hatch-cli   -- --state-dir ./.hatch install --file examples/manifests/minimal.toml --allow-unsigned
cargo run -p hatch-cli   -- --state-dir ./.hatch run minimal --seconds 2
cargo run -p hatch-cli   -- --state-dir ./.hatch audit
cargo run -p hatch-cli   -- --state-dir ./.hatch daemon stop
```

For a real MCP server, install `examples/manifests/filesystem.toml`. It
wraps the official `@modelcontextprotocol/server-filesystem` scoped to
`$PROJECT_ROOT`. Requires Node:

```bash
cargo run -p hatch-cli -- --state-dir ./.hatch \
    install --file examples/manifests/filesystem.toml --allow-unsigned
cargo run -p hatch-cli -- --state-dir ./.hatch run filesystem --seconds 5
```

Daemon flags worth knowing:

- `--enable-proxy` — start the SNI proxy and DNS allowlist resolver.
- `--real-sandbox` — use the Linux or macOS backend instead of the passthrough stub.
- `--metrics-addr 127.0.0.1:9876` — expose Prometheus metrics.

## CLI

```
hatch status                  daemon health
hatch list [--running]        installed manifests / running servers
hatch ps                      running servers
hatch run NAME                spawn an installed manifest
hatch stop TARGET             stop a running server
hatch inspect TARGET          show a running server's compiled policy
hatch install --file PATH     install a local manifest
hatch uninstall NAME
hatch approve ID [--remember once|session|manifest-version]
hatch deny ID
hatch audit [--tui]           tail / interactive audit viewer
hatch observe -- CMD ...      run with syscall tracing, emit candidate manifest
hatch manifest validate PATH
hatch manifest explain PATH
hatch manifest show NAME
hatch manifest diff NAME PATH
hatch manifest edit NAME              open in $EDITOR, validate, reinstall
hatch config status [--workspace]
hatch config sync [--host H] [--force] [--workspace | --workspace-path DIR]
hatch config unsync [--host H] [--workspace | --workspace-path DIR]
hatch registry install-bundle PATH
hatch registry list
hatch registry verify NAME
hatch debug audit-verify [--path FILE | --all]   verify the audit hash chain
hatch debug profile NAME              render the compiled platform profile
hatch daemon status | stop
hatch doctor
hatch version
```

`--format json` switches structured output. Exit codes: 0 success, 11 not
found, 12 manifest invalid, 13 signature failed, 14 approval timeout, 15
spawn failed.

## Manifest

```toml
schema_version = "1.0"
name = "github"
version = "1.2.0"
description = "Official GitHub MCP server"

[command]
program = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]

[network]
allow_https = ["api.github.com", "*.githubusercontent.com"]
allow_dns   = ["api.github.com", "*.githubusercontent.com"]

[filesystem]
read  = []
write = []
tmpfs = ["/tmp"]

[env]
passthrough = ["GITHUB_TOKEN"]

[exec]
allow_subprocess = false

[resources]
memory_mb = 512
cpu_percent = 50
pids_max = 50
nofile = 256
tool_call_timeout_seconds = 60

[tool_policy]
require_approval = ["delete_*", "admin_*"]

[[tool_policy.rules]]
tool = "create_or_update_file"
when = "args.branch in ['main', 'master', 'production']"
action = "require_approval"

[platform.linux]
seccomp_preset = "strict"
landlock = true

[platform.macos]
endpoint_security = false
```

Full schema reference: [`docs/src/reference/manifest-schema.md`](docs/src/reference/manifest-schema.md)
and [`manifests/schema/manifest.schema.json`](manifests/schema/manifest.schema.json).


## Status

Not yet done:

- **Live Linux backend validation.** The workspace cross-compiles cleanly for
  `x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu` in CI, but the
  namespace + cgroup + iptables wiring in `hatch-sandbox-linux` and the
  Landlock + seccomp filters in `hatch-linux-helper` have not yet run
  end-to-end on a real host (kernel 5.13+, user namespaces, cgroups v2). This
  is the top priority — the core enforcement is unproven on real hardware.
- **macOS distribution signing.** Requires Apple Developer enrollment; the
  notarization scripts (`scripts/notarize-macos.sh`) read the credentials from
  the environment or Action secrets when available.
- **macOS Endpoint Security** entitlement (scaffolded, pending Apple grant).
