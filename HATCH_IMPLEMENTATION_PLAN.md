# Hatch: Implementation Plan

**Capability-based isolation for AI tool servers.**

Hatch sandboxes MCP (Model Context Protocol) servers and other AI tool runners on Linux and macOS, enforcing per-server network, filesystem, and protocol-level policies declared in signed manifests.

This document is the complete, gap-free implementation specification for the project. It is written to be sufficient on its own: someone reading only this file should be able to build, ship, and maintain Hatch 1.0.

---

## Table of contents

1. [Project overview](#1-project-overview)
2. [Threat model](#2-threat-model)
3. [System architecture](#3-system-architecture)
4. [Repository layout](#4-repository-layout)
5. [Toolchain and dependencies](#5-toolchain-and-dependencies)
6. [Manifest specification](#6-manifest-specification)
7. [Layer 0 — Persistence and observability](#7-layer-0--persistence-and-observability)
8. [Layer 1 — Egress control](#8-layer-1--egress-control)
9. [Layer 2 — Sandbox backends](#9-layer-2--sandbox-backends)
10. [Layer 3 — Policy engine](#10-layer-3--policy-engine)
11. [Layer 4 — Protocol mediation](#11-layer-4--protocol-mediation)
12. [Layer 5 — User interface](#12-layer-5--user-interface)
13. [Daemon IPC protocol](#13-daemon-ipc-protocol)
14. [Host integration](#14-host-integration)
15. [Manifest registry](#15-manifest-registry)
16. [Documentation site](#16-documentation-site)
17. [Build sequence](#17-build-sequence)
18. [Testing strategy](#18-testing-strategy)
19. [Release and signing](#19-release-and-signing)
20. [Operational concerns](#20-operational-concerns)
21. [Open questions and deferred decisions](#21-open-questions-and-deferred-decisions)
22. [Week-one checklist](#22-week-one-checklist)

---

## 1. Project overview

### 1.1 Mission

Make it safe to run third-party AI tool servers (MCP servers and equivalents) on a developer's machine by enforcing declared capability boundaries at the OS layer and the protocol layer.

### 1.2 Scope

**In scope for 1.0:**

- Sandboxing local stdio-transport MCP servers on Linux and macOS.
- Network egress control via SNI-filtering proxy and allowlist DNS resolver.
- Filesystem isolation via OS-native primitives.
- Syscall filtering on Linux (seccomp); kernel-enforced policy on macOS (sandbox-exec, PF).
- Protocol-level interception: tool-call policy, argument inspection, optional approval flows, response filtering.
- Signed community manifest registry.
- CLI-first user experience with host config rewriting for major MCP hosts.
- Audit log and Prometheus metrics.

**Out of scope for 1.0:**

- Windows support.
- Remote MCP servers (HTTPS/SSE transport). Different trust model; covered by OAuth scoping.
- Sandboxing the MCP host itself (Claude Desktop, Cursor, etc.).
- GUI applications. CLI + system notifications only.
- Sandboxing arbitrary non-MCP AI tools (long-term direction; not a 1.0 commitment).
- TLS interception. SNI filtering only — never break the trust boundary by terminating TLS.

### 1.3 Non-goals

- Replacing Docker / Podman for general-purpose containerization.
- Becoming a runtime for production AI agents (that's downstream; hatch is local-dev infrastructure).
- Bypassing prompt injection at the model layer. Hatch limits *impact*, not *occurrence*.

### 1.4 Naming and identity

- Project name: **hatch** (lowercase, no caps anywhere).
- Binaries: `hatch`, `hatch-daemon`, `hatch-shim`.
- GitHub org: `malwarebo` (verify availability; fall back to `hatchproject`).
- Domain: `hatch.sh` (primary), `hatch.dev` (fallback).
- License: Apache 2.0 with patent grant.

---

## 2. Threat model

This section is the contract between hatch and its users. Every claim here must be defensible.

### 2.1 Assets being protected

- User credentials on disk (SSH keys, cloud credentials, API tokens, password manager databases).
- Source code and project files outside the scope a specific tool server should see.
- Network identity (ability to make authenticated requests from the user's machine to arbitrary destinations).
- Local resources (CPU, memory, file descriptors, processes).

### 2.2 Adversaries

- **Malicious server author** publishes a fake or typosquatted MCP server to npm, PyPI, or a Git host.
- **Supply-chain attacker** compromises a legitimate MCP server's dependency.
- **Indirect prompt injection actor** plants instructions in content the LLM reads (webpages, PDFs, issues, emails) that cause the agent to invoke tools with malicious arguments.
- **Curious or compromised legitimate server** that misbehaves in ways the author did not intend (bugs, telemetry overreach).

### 2.3 Trust assumptions

The following are *trusted* (in the user's TCB):

- The host OS kernel.
- The MCP host application (Claude Desktop, Cursor, Claude Code, etc.).
- The hatch daemon, CLI, shim binaries (after signature verification at install time).
- The hatch manifest signing keys.
- The user's package manager and the integrity of installed packages it verifies.

The following are *untrusted*:

- Any MCP server binary, script, or library.
- All dependencies of MCP servers.
- Any content the LLM processes (web pages, files, third-party API responses).
- Any input arriving over the network.

### 2.4 What hatch protects against

1. Malicious server reading files outside its declared filesystem scope (`~/.ssh`, `~/.aws`, sibling projects, etc.).
2. Malicious server exfiltrating data to attacker-controlled hosts (network egress restricted to declared destinations).
3. Malicious server exhausting resources (cgroups/setrlimit limits).
4. Server tricked by prompt injection into invoking a destructive tool (protocol mediation, approval flows).
5. Server tricked into invoking a legitimate tool with malicious arguments (CEL-based argument rules).
6. Server leaking secrets in tool responses to the LLM (response filters).
7. Compromised server spawning subprocesses to bypass its constraints (subprocess policy + seccomp `execve` filtering on Linux).

### 2.5 What hatch does NOT protect against

Documented explicitly because honesty about limits is what makes the protections credible:

1. **The MCP host itself being compromised.** If Claude Desktop is malicious, hatch is bypassed.
2. **The LLM choosing to misuse a tool whose use is allowed by manifest.** If the manifest allows `filesystem.write` to `$PROJECT_ROOT`, the LLM can be tricked into corrupting `$PROJECT_ROOT/.env`.
3. **DNS-tunneled exfiltration to allowlisted domains.** If the manifest allows `*.example.com`, a compromised server can encode data in subdomain queries.
4. **Side-channel attacks** (timing, cache, power).
5. **Kernel exploits.** Out of scope; mitigated by keeping the OS patched.
6. **Network attacks on allowlisted destinations.** If `api.github.com` is compromised, hatch doesn't help.
7. **User-supplied permissive manifests.** A manifest that grants `read=["/"]` defeats the purpose; the risk-score system warns but does not prevent.
8. **Account compromise on allowlisted services.** Your GitHub token used legitimately by a sandboxed server is still your GitHub token.
9. **Windows.** Not supported.
10. **Remote MCP servers.** Hatch sandboxes the local stdio transport; remote servers are out of scope.

### 2.6 Per-platform guarantee table

| Capability | Linux | macOS (default) | macOS (entitled) |
|---|---|---|---|
| Filesystem access restricted to manifest paths | Kernel-enforced (mount namespace + Landlock) | Kernel-enforced (TrustedBSD via sandbox-exec) | Kernel-enforced + ES monitoring |
| Network egress restricted to allowlist | Kernel-enforced (netns, no other route) | Kernel-enforced (PF rules by UID) | Same + ES connect events |
| DNS restricted to allowlist | Kernel-enforced (no other resolver reachable) | Cooperation-enforced (PF blocks alt resolvers) | Same |
| Syscall surface restricted | Yes (seccomp-bpf) | No platform primitive | Partial (ES auth events) |
| Resource limits enforced | Yes (cgroups v2) | Yes (setrlimit) | Yes |
| Subprocess spawning restricted | Yes (seccomp `execve` filter) | Yes (sandbox-exec `process-exec`) | Yes |
| No privilege escalation possible | Yes (caps dropped, no_new_privs) | Yes (non-root UID, no setuid binaries reachable) | Yes |

---

## 3. System architecture

### 3.1 Component diagram

```
+--------------------------------------------------------------+
|                       MCP HOST                               |
|       (Claude Desktop / Cursor / Claude Code / etc.)         |
+----------------------------+---------------------------------+
                             | spawns (rewritten config)
                             v
+--------------------------------------------------------------+
|                     hatch-shim                               |
|  Per-server entry point. Talks to daemon, pumps stdio.       |
+----------------------------+---------------------------------+
                             | unix socket
                             v
+--------------------------------------------------------------+
|                     hatch-daemon                             |
|  Long-running. Owns sandbox lifecycle, policy decisions,     |
|  proxy, audit log, registry cache.                           |
+----+--------+--------+--------+---------+--------+-----------+
     |        |        |        |         |        |
     v        v        v        v         v        v
+--------+ +------+ +------+ +-------+ +------+ +--------+
|Sandbox | |Policy| |Proxy | |Audit  | |State | |Approval|
|backend | |engine| |+ DNS | |log    | |(SQL) | |broker  |
+---+----+ +------+ +------+ +-------+ +------+ +---+----+
    |                                                |
    v                                                v
+--------------------+                       +-----------------+
|  Sandboxed server  |                       |  System notif.  |
|  (MCP binary)      |                       |  (D-Bus / NSO)  |
+--------------------+                       +-----------------+
```

### 3.2 Layered model

| Layer | Name | Concerns |
|---|---|---|
| 5 | User interface | CLI, host config rewriting, TUI |
| 4 | Protocol mediation | JSON-RPC interception, tool policy, approvals, response filters |
| 3 | Policy engine | Manifest parsing, validation, compilation, signature verification |
| 2 | Sandbox backends | Per-OS isolation primitives |
| 1 | Egress control | SNI proxy, DNS resolver |
| 0 | Persistence & observability | Audit log, SQLite state, metrics |

Lower layers know nothing about higher layers. Higher layers compose lower-layer services via well-defined interfaces.

### 3.3 Process model

Three binaries:

- **`hatch`** — CLI. Short-lived. Talks to the daemon over a unix socket. Used for installation, configuration, inspection, approval.
- **`hatch-daemon`** — long-running. One per user session. Manages sandboxed servers, runs the egress proxy and DNS resolver, owns audit log and SQLite state.
- **`hatch-shim`** — per-sandboxed-server bridge. Spawned by the MCP host. Tiny. Pumps stdio between host and the daemon-managed sandboxed server. Intercepts JSON-RPC for policy decisions.

### 3.4 Data flow for a sandboxed tool call

1. User asks Claude Desktop to do something requiring a sandboxed MCP server.
2. Claude Desktop sends a `tools/call` JSON-RPC message to the server's stdin.
3. Stdin is actually the shim. Shim reads the message.
4. Shim parses the message (simd-json), extracts tool name + args.
5. Shim sends a policy query to the daemon over its unix socket.
6. Daemon evaluates the manifest's `tool_policy.rules` against the args (CEL).
7. Daemon decides: allow, deny, or require approval.
8. If approval required: daemon emits a system notification; user approves/denies; daemon responds to shim.
9. Shim either forwards the message to the sandboxed server's stdin, or returns a JSON-RPC error to Claude Desktop.
10. Sandboxed server processes the call. To do so it may:
    - Make a network connection — routed through the SNI proxy, filtered against the manifest's `network.allow_https`.
    - Read files — restricted by mount namespace (Linux) or sandbox-exec rules (macOS).
    - Make DNS queries — answered by the daemon's allowlist resolver.
11. Server writes a JSON-RPC response to its stdout.
12. Shim reads it, applies `response_filters` (redaction of secrets), forwards to host.
13. Every step from 3 onward emits structured audit events.

### 3.5 Lifetimes

- The daemon starts on user login (launchd LaunchAgent on macOS; systemd user service on Linux) and runs until logout.
- A sandboxed server starts when the host invokes the shim and lives until the host closes the connection or the server exits.
- The shim lives for the duration of one server session.
- The CLI lives for the duration of one command.

---

## 4. Repository layout

Two GitHub repositories under `malwarebo`.

### 4.1 `malwarebo/hatch` — main project

```
hatch/
├── Cargo.toml                      # workspace root
├── rust-toolchain.toml             # pinned Rust version
├── deny.toml                       # cargo-deny config
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                  # build + test on Linux + macOS
│   │   ├── release.yml             # signed release builds
│   │   ├── security-audit.yml      # cargo-audit, cargo-deny weekly
│   │   └── fuzz.yml                # nightly fuzzing
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   ├── feature_request.md
│   │   └── security.md             # redirects to SECURITY.md
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── dependabot.yml
├── SECURITY.md
├── LICENSE                         # Apache 2.0
├── NOTICE
├── CODE_OF_CONDUCT.md              # Contributor Covenant
├── CONTRIBUTING.md
├── README.md
├── crates/
│   ├── hatch-cli/                  # CLI entry point (binary)
│   ├── hatch-daemon/               # daemon (binary)
│   ├── hatch-shim/                 # shim (binary)
│   ├── hatch-core/                 # shared types, manifest schema
│   ├── hatch-sandbox/              # sandbox trait + dispatch
│   ├── hatch-sandbox-linux/        # Linux backend (target-gated)
│   ├── hatch-sandbox-macos/        # macOS backend (target-gated)
│   ├── hatch-proxy/                # SNI proxy + DNS resolver
│   ├── hatch-protocol/             # JSON-RPC + MCP types + CEL eval
│   ├── hatch-audit/                # structured audit logging
│   ├── hatch-state/                # SQLite state management
│   ├── hatch-registry/             # manifest registry client + signature verification
│   ├── hatch-hostcfg/              # MCP host config rewriting
│   └── hatch-ipc/                  # daemon IPC protocol types
├── docs/                           # mdBook source
│   ├── book.toml
│   └── src/
├── examples/
│   ├── manifests/                  # sample manifests
│   └── malicious-server/           # demo "attacker" server for testing
├── tests/                          # workspace-level integration tests
├── fuzz/                           # cargo-fuzz targets
└── scripts/
    ├── dev-setup.sh
    ├── release.sh
    └── notarize-macos.sh
```

### 4.2 `malwarebo/manifests` — community registry

```
manifests/
├── README.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── LICENSE                         # CC0 for manifests
├── .github/
│   └── workflows/
│       ├── validate.yml            # PR validation
│       ├── smoke-test.yml          # run servers with proposed manifests
│       └── release.yml             # build signed manifest bundles
├── schema/
│   ├── manifest.schema.json        # JSON Schema for manifests
│   └── manifest-v1.toml.template
├── signing/
│   ├── README.md                   # how signing works
│   ├── pubkeys/                    # current and past public keys
│   │   ├── 2026-active.pub
│   │   └── 2025-revoked.pub
│   └── policy.md                   # key rotation, trust policy
├── servers/
│   ├── github/
│   │   ├── manifest.toml
│   │   ├── README.md
│   │   ├── CHANGELOG.md
│   │   └── test/
│   │       ├── smoke.sh
│   │       └── expected.json
│   ├── filesystem/
│   ├── linear/
│   └── ...
└── scripts/
    ├── sign-release.sh
    ├── validate-manifest.sh
    └── new-server.sh               # scaffold a new manifest dir
```

---

## 5. Toolchain and dependencies

### 5.1 Rust toolchain

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.83.0"                  # pin at project kickoff; update deliberately
components = ["rustfmt", "clippy", "rust-src"]
targets = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
           "x86_64-apple-darwin", "aarch64-apple-darwin"]
```

Edition: latest stable (2024 if available at project kickoff, otherwise 2021).

### 5.2 Core dependencies (workspace-level)

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime (full features for daemon, minimal for shim) |
| `serde`, `serde_json`, `toml` | Serialization |
| `clap` (v4, derive) | CLI argument parsing |
| `tracing`, `tracing-subscriber` | Structured logging |
| `rustix` | Safe syscall wrappers (replaces `nix`) |
| `rusqlite` (bundled) | SQLite for state |
| `sha2`, `blake3` | Hashing |
| `ed25519-dalek` | Manifest signature verification |
| `rustls`, `tokio-rustls` | TLS for the proxy (no OpenSSL dependency) |
| `hickory-resolver`, `hickory-server` | DNS resolver and server |
| `ratatui`, `crossterm` | TUI |
| `prometheus` | Metrics endpoint |
| `thiserror` | Error types in library crates |
| `anyhow` | Error handling in binary crates |
| `simd-json` | Fast JSON in shim hot path |
| `cel-interpreter` | CEL expression evaluation for argument rules |
| `notify` | File watching for config sync |
| `uuid` (v4) | Identifier generation |
| `time` | Timestamps |

### 5.3 Linux-specific dependencies

| Crate | Purpose |
|---|---|
| `seccompiler` | Compile seccomp BPF filters |
| `landlock` | Landlock LSM bindings |
| `cgroups-rs` | cgroups v2 (or implement directly via filesystem ops) |
| `netlink-packet-route`, `rtnetlink` | netns and veth setup |
| `aya` | eBPF for observation mode (optional alternative to ptrace) |

### 5.4 macOS-specific dependencies

| Crate | Purpose |
|---|---|
| `core-foundation` | CF types |
| `security-framework` | Keychain, code signing |
| `libproc` | Process introspection |
| `objc2` | Obj-C bindings for notification helpers |

Custom FFI bindings (generated via `bindgen` in `build.rs`):
- `sandbox_init`, `sandbox_init_with_parameters` (from `<sandbox.h>`)
- Endpoint Security framework (gated behind entitlement feature flag)

### 5.5 Build-time tools

- `cargo-deny` — license and advisory checks (CI)
- `cargo-audit` — vulnerability database checks (CI)
- `cargo-fuzz` — fuzzing
- `cargo-llvm-cov` — code coverage
- `cargo-nextest` — faster test runner
- `bindgen` — FFI bindings (build.rs in macOS crate)

### 5.6 Forbidden dependencies

These should not appear in the dependency tree:

- OpenSSL (use rustls). Reason: avoid system-OpenSSL ABI issues, reduce attack surface.
- `nix` (use `rustix`). Reason: rustix is faster, smaller, less unsafe.
- Anything GPL. Reason: keeps the project Apache-compatible.

Enforce via `cargo-deny` ban list.

---

## 6. Manifest specification

### 6.1 Format and version

- Format: TOML.
- Schema version field required: `schema_version = "1.0"`.
- Backward compatibility: daemon supports the last two major schema versions.

### 6.2 Complete schema

```toml
# ─── Required metadata ────────────────────────────────────────
schema_version = "1.0"
name = "github"                            # unique, lowercase, hyphenated
version = "1.2.0"                          # semver
description = "Official GitHub MCP server"
homepage = "https://github.com/modelcontextprotocol/servers"   # optional
license = "MIT"                            # SPDX identifier, optional

# ─── How to launch the server ─────────────────────────────────
[command]
program = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
working_dir = "$HATCH_RUNTIME_DIR"         # template vars supported

# ─── Integrity verification ───────────────────────────────────
[integrity]
# For npm packages:
npm_package = "@modelcontextprotocol/server-github"
npm_version = "0.6.2"
npm_integrity = "sha512-..."               # from package-lock.json
# For pip:
# pip_package = "..."
# pip_version = "..."
# pip_hash = "sha256:..."
# For git:
# git_repo = "https://github.com/..."
# git_ref = "v1.2.0"
# git_commit = "deadbeef..."

# ─── Network policy ───────────────────────────────────────────
[network]
allow_https = ["api.github.com", "*.githubusercontent.com"]
allow_dns   = ["api.github.com", "*.githubusercontent.com"]
allow_http  = false                        # plaintext HTTP, default false
rate_limit_mbps = 10
max_bytes_per_connection_mb = 100

# ─── Filesystem policy ────────────────────────────────────────
[filesystem]
read   = []                                # absolute paths, supports templates
write  = []                                # implicitly readable
tmpfs  = ["/tmp"]                          # ephemeral writable scratch
deny   = []                                # explicit overrides

# ─── Environment variables ────────────────────────────────────
[env]
passthrough = ["GITHUB_TOKEN"]
set = { NODE_OPTIONS = "--no-deprecation" }
unset = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]

# ─── Subprocess policy ────────────────────────────────────────
[exec]
allow_subprocess = false
allow_binaries = []                        # absolute paths if allow_subprocess

# ─── Resource limits ──────────────────────────────────────────
[resources]
memory_mb = 512
cpu_percent = 50
pids_max = 50
nofile = 256
tool_call_timeout_seconds = 60

# ─── Protocol-level policy (Layer 4) ──────────────────────────
[tool_policy]
require_approval = ["delete_*", "force_push", "admin_*"]
deny = ["execute_arbitrary_code"]

[[tool_policy.rules]]
tool = "filesystem.write"
when = "args.path.startsWith('/etc/')"
action = "deny"

[[tool_policy.rules]]
tool = "git.push"
when = "args.branch in ['main', 'master', 'production']"
action = "require_approval"

[[tool_policy.response_filters]]
pattern = "(?i)(api[_-]?key|secret|token)\\s*[:=]\\s*[\\w.-]+"
replacement = "[REDACTED]"

# ─── Platform-specific overrides ──────────────────────────────
[platform.linux]
seccomp_preset = "strict"                  # permissive | default | strict
landlock = true
extra_caps = []

[platform.macos]
endpoint_security = false                  # require entitled daemon
extra_sbpl = ""                            # raw sandbox-exec rules

# ─── Signature (filled in by registry signing) ────────────────
[signature]
key_id = "hatch-registry-2026"
algorithm = "ed25519"
sig = "..."
signed_at = "2026-05-01T00:00:00Z"
```

### 6.3 Template variables

Resolved at server launch:

| Variable | Meaning |
|---|---|
| `$HOME` | User's home directory |
| `$HATCH_RUNTIME_DIR` | Per-server ephemeral scratch, deleted on exit |
| `$HATCH_STATE_DIR` | Per-server persistent state |
| `$PROJECT_ROOT` | Current project directory (host-provided, falls back to CWD) |
| `$XDG_CONFIG_HOME`, `$XDG_DATA_HOME` | Standard XDG paths |
| `$USER` | Username |

Templates resolve before policy compilation. Unresolved template vars cause manifest load to fail with a clear error.

### 6.4 Validation rules

**Structural (JSON Schema):**

- All required fields present.
- Field types correct.
- Enum fields use valid values.

**Semantic:**

- `name` matches `^[a-z0-9][a-z0-9-]{0,62}$`.
- `version` is valid semver.
- `filesystem.write` paths cannot be ancestors of: `/`, `/etc`, `/usr`, `/bin`, `/sbin`, `/boot`, `/sys`, `/proc`.
- `filesystem.read` warnings (not errors) for: `$HOME` (overly broad), `/`, ancestors of credential locations.
- `exec.allow_binaries` paths must be absolute.
- `network.allow_http = true` requires a comment in the manifest justifying it (parsed as a leading `# justification: ...` comment line).
- `resources.memory_mb >= 64`.
- At least one of `network.allow_https`, `network.allow_dns`, or `exec.allow_subprocess` should be non-empty unless the server is purely computational (warning only).
- CEL expressions in `tool_policy.rules.when` must parse and type-check against a stub context.
- Regex patterns in `response_filters` must compile.

**Risk scoring:**

A heuristic score helps users gauge permission breadth. Computed at install time and shown by `hatch manifest explain`.

| Condition | Score delta |
|---|---|
| Per network destination (specific hostname) | +5 |
| Per wildcard network destination | +15 |
| `allow_http = true` | +30 |
| Per filesystem read path | +10 |
| Per filesystem write path | +20 |
| `read = ["$HOME"]` or similar broad path | +100 |
| `allow_subprocess = true` | +50 |
| Per binary in `allow_binaries` | +5 |
| `seccomp_preset = "permissive"` | +100 |
| `seccomp_preset = "default"` | +30 |
| `endpoint_security = false` on macOS with subprocess | +200 |
| Each unsigned manifest | +500 |

Score thresholds:
- 0–100: low risk.
- 100–300: moderate, normal for many servers.
- 300–600: high, review carefully.
- 600+: very high, warning shown loudly at install.

### 6.5 Signature format

```toml
[signature]
key_id = "hatch-registry-2026"
algorithm = "ed25519"
sig = "base64-encoded-64-bytes"
signed_at = "2026-05-01T00:00:00Z"
```

The signed content is the manifest TOML with the `[signature]` section removed, canonicalized (sorted keys, no comments, normalized whitespace), UTF-8 encoded. Signature verification:

1. Look up `key_id` in bundled trust store.
2. Reject if key is in revocation list.
3. Reject if `signed_at` is more than 2 years old without a re-sign.
4. Verify ed25519 signature.

---

## 7. Layer 0 — Persistence and observability

### 7.1 Filesystem layout

**Linux (XDG):**

| Purpose | Path |
|---|---|
| Config | `$XDG_CONFIG_HOME/hatch/` (`~/.config/hatch/`) |
| State | `$XDG_STATE_HOME/hatch/` (`~/.local/state/hatch/`) |
| Cache | `$XDG_CACHE_HOME/hatch/` (`~/.cache/hatch/`) |
| Runtime | `$XDG_RUNTIME_DIR/hatch/` (`/run/user/$UID/hatch/`) |
| Daemon socket | `$XDG_RUNTIME_DIR/hatch/daemon.sock` |
| Audit log | `$XDG_STATE_HOME/hatch/audit/` |
| SQLite DB | `$XDG_STATE_HOME/hatch/state.db` |

**macOS:**

| Purpose | Path |
|---|---|
| Config | `~/Library/Application Support/hatch/config/` |
| State | `~/Library/Application Support/hatch/state/` |
| Cache | `~/Library/Caches/hatch/` |
| Runtime | `$TMPDIR/hatch/` |
| Logs | `~/Library/Logs/hatch/` |
| Daemon socket | `$TMPDIR/hatch/daemon.sock` |

All directories created with mode 0700.

### 7.2 Audit log

Format: JSONL (one JSON object per line). One file per day, rotated at midnight UTC. Compressed (`zstd`) after rotation. Retained 90 days by default (configurable).

**Event schema:**

```json
{
  "ts": "2026-05-13T10:30:45.123456Z",
  "event_id": "01HXYZABCDEF...",
  "server": "github",
  "server_id": "01HXYZ...",
  "host": "claude-desktop",
  "event": "tool_call",
  "fields": {
    "tool": "create_issue",
    "args_hash": "sha256:abc...",
    "args_summary": {"repo": "user/repo", "title": "[redacted-32-chars]"},
    "decision": "allow",
    "rule_matched": null,
    "latency_ms": 230
  }
}
```

**Event types:**

| Event | Fields |
|---|---|
| `daemon_start` | version, pid |
| `daemon_stop` | reason |
| `server_spawn` | server, server_id, manifest_version, sandbox_backend |
| `server_exit` | server_id, exit_code, duration_seconds |
| `tool_call` | tool, args_hash, args_summary, decision, rule_matched, latency_ms |
| `tool_response` | tool, response_size_bytes, redactions_applied |
| `fs_denied` | path, op (read/write), syscall |
| `net_attempt` | host, port, decision |
| `net_denied` | host, port, reason |
| `policy_violation` | rule, details |
| `approval_requested` | approval_id, tool, args_summary |
| `approval_granted` | approval_id, by, ttl_seconds |
| `approval_denied` | approval_id, by, reason |
| `signature_verified` | manifest_name, key_id |
| `signature_failed` | manifest_name, reason |

**Args summarization:**

Tool call arguments often contain secrets or large payloads. The audit log stores:
- `args_hash`: SHA-256 of canonicalized args.
- `args_summary`: object with keys preserved, values redacted if they match secret patterns or exceed 64 chars (shown as `[redacted-N-chars]`).

Full args are never logged. If a forensic investigation needs them, the daemon supports `hatch debug --capture-args <server>` which logs full args to a separate, mode-0600 file with explicit user opt-in.

**Append-only enforcement:**

- Logs opened with `O_APPEND`.
- After rotation, previous day's file is `chmod 0400`.
- Optional: hash chain — each line includes `prev_hash` of the previous line, making tampering detectable.

### 7.3 SQLite state schema

```sql
-- Schema version for migrations
CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

-- Installed manifests
CREATE TABLE manifests (
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('bundled', 'registry', 'local', 'git')),
    signature_verified INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    installed_at INTEGER NOT NULL,
    content TEXT NOT NULL,                  -- raw TOML
    compiled_cache BLOB,                    -- bincode-serialized CompiledPolicy
    PRIMARY KEY (name, version)
);

CREATE INDEX idx_manifests_name ON manifests(name);

-- Currently running sandboxed servers
CREATE TABLE running_servers (
    id TEXT PRIMARY KEY,                    -- UUID v4
    manifest_name TEXT NOT NULL,
    manifest_version TEXT NOT NULL,
    host TEXT,
    pid INTEGER,
    sandbox_backend TEXT NOT NULL,
    sandbox_id TEXT NOT NULL,               -- backend-specific
    started_at INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('starting', 'running', 'exiting', 'crashed')),
    FOREIGN KEY (manifest_name, manifest_version) REFERENCES manifests(name, version)
);

-- Pending and historical approvals
CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    args_hash TEXT NOT NULL,
    args_summary TEXT NOT NULL,
    decision TEXT CHECK (decision IN ('allow', 'deny', 'pending', 'timeout')),
    requested_at INTEGER NOT NULL,
    decided_at INTEGER,
    remembered_until INTEGER                -- session memory
);

CREATE INDEX idx_approvals_pending ON approvals(decision) WHERE decision = 'pending';
CREATE INDEX idx_approvals_remember ON approvals(server_id, tool, args_hash, remembered_until);

-- Registry manifest cache metadata
CREATE TABLE registry_cache (
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    bundle_sha256 TEXT NOT NULL,
    PRIMARY KEY (name, version)
);

-- UID pool (macOS) / sandbox allocation
CREATE TABLE sandbox_uids (
    uid INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    server_id TEXT,                         -- NULL if free
    allocated_at INTEGER
);

-- Daemon-level config and feature flags
CREATE TABLE daemon_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

Migrations live in `crates/hatch-state/migrations/`, applied at daemon startup.

### 7.4 Metrics

Prometheus endpoint on `127.0.0.1:9876/metrics`. Disabled by default; enable via daemon config or `--metrics` flag.

| Metric | Type | Labels |
|---|---|---|
| `hatch_daemon_uptime_seconds` | gauge | |
| `hatch_servers_running` | gauge | |
| `hatch_servers_spawned_total` | counter | server |
| `hatch_tool_calls_total` | counter | server, tool, decision |
| `hatch_fs_denials_total` | counter | server, op |
| `hatch_net_attempts_total` | counter | server, decision |
| `hatch_proxy_bytes_total` | counter | server, direction |
| `hatch_approval_latency_seconds` | histogram | |
| `hatch_tool_call_latency_seconds` | histogram | server, tool |
| `hatch_audit_events_total` | counter | event_type |
| `hatch_audit_write_errors_total` | counter | |

---

## 8. Layer 1 — Egress control

### 8.1 SNI-filtering HTTPS proxy

A transparent TCP proxy that inspects the TLS ClientHello to extract the SNI and routes based on a per-sandbox allowlist. No TLS termination.

**Listener:**

- Linux: listens on a host-side address in each sandbox's network namespace bridge. Inside the netns, the proxy is reachable at a fixed IP (e.g., `10.99.<sandbox-id>.1:443`).
- macOS: listens on `127.0.0.1:<dynamic-port>`. PF rules redirect outgoing 443 from the sandboxed UID to this port.

**Connection handling:**

1. Accept TCP connection.
2. Identify the originating sandbox (Linux: source IP maps to sandbox-id; macOS: source port + UID lookup via `proc_pidinfo`).
3. Look up the manifest's allowlist for that sandbox.
4. Read up to 8 KB into a buffer; parse TLS ClientHello.
5. Extract SNI from the `server_name` extension.
6. Match SNI against allowlist (suffix match for wildcards: `*.example.com` matches `a.example.com` but not `a.b.example.com`).
7. On match: resolve the SNI to an IP (via the daemon's DNS resolver), open an upstream connection, `splice(2)` traffic both directions on Linux, `io::copy` on macOS.
8. On mismatch: send TCP RST, log a `net_denied` audit event.

**Rate limiting:**

Token-bucket per server, refilled at `rate_limit_mbps`. Bucket size = 2 seconds of capacity. Implemented by throttling read calls on the sandbox-side socket.

**Per-connection byte cap:**

If `max_bytes_per_connection_mb` set, count bytes; close the connection when exceeded. Defense against a single huge exfil to an allowlisted host.

### 8.2 DNS resolver

Tiny DNS server using `hickory-server`.

**Listener:**

- Linux: in each sandbox's netns, the resolver is at `10.99.<sandbox-id>.1:53`. The sandbox's `/etc/resolv.conf` is synthesized to point here.
- macOS: shared resolver at `127.0.0.1:<dynamic-port>`. PF rules redirect outgoing 53 from sandboxed UIDs to this port.

**Query handling:**

1. Receive query.
2. Identify originating sandbox (same as proxy).
3. Look up manifest's `network.allow_dns` list.
4. Match query name against allowlist (suffix + wildcard).
5. On match: forward to system resolver (cached). Return result with TTL clamped to ≤300s.
6. On mismatch: return NXDOMAIN. Log `net_denied` audit event with `reason: dns`.

**Handles only A, AAAA, CNAME.** Other types (TXT, MX, SRV) return REFUSED — they're rarely needed by MCP servers and reduce DNS-tunneling surface.

### 8.3 Why this combination is strong

- A server cannot reach an unallowed IP because it cannot resolve the hostname (DNS layer).
- A server that hardcodes an IP cannot establish TLS without an SNI-allowed hostname (proxy layer).
- A server that uses an allowlisted hostname is still rate-limited and capped per connection.
- All three layers log every attempt for audit.

### 8.4 Known limitations (documented in threat model)

- DNS-tunneled exfiltration via subdomain queries to allowlisted domains. Mitigated only by tight allowlists.
- Server that splits an exfil across many small connections to allowlisted hosts. Mitigated by rate limit but not eliminated.
- Server that uses a custom DNS resolver bypassing `/etc/resolv.conf` — blocked on Linux (no other resolver reachable from netns), partially blocked on macOS (PF blocks alt resolvers).

---

## 9. Layer 2 — Sandbox backends

### 9.1 Sandbox trait

```rust
// crates/hatch-sandbox/src/lib.rs

pub trait Sandbox: Send + Sync {
    fn name(&self) -> &str;

    fn spawn(&self, policy: &CompiledPolicy, command: &Command)
        -> Result<SandboxedProcess, SandboxError>;

    fn supports_seccomp(&self) -> bool;
    fn supports_landlock(&self) -> bool;
    fn supports_endpoint_security(&self) -> bool;
}

pub struct SandboxedProcess {
    pub id: String,
    pub pid: u32,
    pub stdin: OwnedFd,
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
    pub sandbox_specific: SandboxData,
}

pub enum SandboxData {
    Linux(LinuxSandboxData),
    Macos(MacosSandboxData),
}
```

### 9.2 Linux backend — full specification

#### 9.2.1 Spawn sequence

1. Validate kernel features (user namespaces, cgroups v2, seccomp, Landlock if requested).
2. Allocate sandbox UUID.
3. Create cgroup at `/sys/fs/cgroup/hatch.slice/server-<uuid>.scope/` and set limits:
   - `memory.max` = `resources.memory_mb * 1024 * 1024`
   - `memory.swap.max` = `0`
   - `cpu.weight` = derived from `resources.cpu_percent`
   - `pids.max` = `resources.pids_max`
   - `io.weight` = `100` (default)
4. Create netns `hatch-<uuid>` via `ip netns add` equivalent (direct `unshare` + bind mount).
5. Create veth pair: `hatch-<uuid>-h` (host) and `hatch-<uuid>-s` (sandbox).
6. Move sandbox end into netns.
7. Assign IPs from `10.99.0.0/16` (e.g., `10.99.<lo>.1/30` host, `10.99.<lo>.2/30` sandbox).
8. Bring up loopback inside netns.
9. Add default route inside netns pointing to host-side veth.
10. Install iptables rules in netns:
    - REDIRECT outgoing 443 → proxy port.
    - REDIRECT outgoing 53 → DNS resolver port.
    - DROP all other outgoing.
    - DROP all incoming.
11. `fork()`. Parent records the child pid. Child:
    - `setns()` into the netns.
    - `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWCGROUP)`.
    - Set up UID/GID mapping (UID 0 in namespace ← daemon's UID outside).
    - Build mount namespace (section 9.2.2).
    - Write `/proc/self/setgroups` = `deny`.
    - Write `/proc/self/uid_map`, `/proc/self/gid_map`.
    - `pivot_root` to the new rootfs.
    - Drop all capabilities (`capset` with empty sets).
    - `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
    - Apply Landlock rules.
    - Join the cgroup (`echo $$ > cgroup.procs`).
    - Set resource limits via `setrlimit`.
    - Apply seccomp filter (must be last; seccomp can prevent some of the above syscalls).
    - `execve()` the server's program.
12. Parent monitors child via `pidfd_open`.

#### 9.2.2 Mount namespace construction

Rootfs at `$XDG_RUNTIME_DIR/hatch/<uuid>/root/`. Built before pivot_root:

```
root/
├── bin       -> /usr/bin     (symlink, target read-only bind-mounted)
├── lib       -> /usr/lib
├── lib64     -> /usr/lib64
├── sbin      -> /usr/sbin
├── usr/      (read-only bind mount from host /usr)
├── etc/
│   ├── resolv.conf     (synthesized: nameserver = in-netns DNS)
│   ├── hosts           (minimal: 127.0.0.1 localhost, ::1 localhost)
│   ├── ssl/            (bind-mounted read-only from host)
│   ├── ca-certificates/(read-only)
│   └── nsswitch.conf   (minimal)
├── tmp/                (tmpfs, size from manifest, default 64 MB)
├── proc/               (procfs with hidepid=2)
├── sys/                (sysfs, read-only, /sys/fs masked)
├── dev/                (devtmpfs subset)
│   ├── null
│   ├── zero
│   ├── random
│   ├── urandom
│   ├── tty
│   ├── stdin  -> /proc/self/fd/0
│   ├── stdout -> /proc/self/fd/1
│   └── stderr -> /proc/self/fd/2
├── home/<user>/        (only if $HOME is in fs.read or fs.write)
└── <manifest fs.read paths bind-mounted ro here>
└── <manifest fs.write paths bind-mounted rw here>
```

#### 9.2.3 Seccomp presets

Defined in `crates/hatch-sandbox-linux/profiles/`:

- `permissive.yaml`
- `default.yaml`
- `strict.yaml`

Compiled at build time into BPF bytecode via `seccompiler`. The compiled filter is loaded with `SECCOMP_FILTER_FLAG_TSYNC` so it applies to all threads.

**Always denied (all presets):**

- `mount`, `umount`, `pivot_root`, `chroot` (after sandbox setup)
- `ptrace`
- `bpf`
- `keyctl`, `add_key`, `request_key`
- `kexec_load`, `kexec_file_load`
- `init_module`, `finit_module`, `delete_module`
- `perf_event_open`
- `userfaultfd`
- `unshare`, `setns` (no nested namespaces)
- `clone` with namespace flags
- `pivot_root`
- `swapon`, `swapoff`
- `reboot`
- `sethostname`, `setdomainname`

**`strict` additionally denies:**

- `execve`, `execveat` (no subprocess; overridden if `allow_subprocess`)
- `socket` for `AF_INET` other than already-established (no new connections; the proxy handles existing)
- Various rarely-needed syscalls

#### 9.2.4 Landlock rules

Built from manifest fs paths. Linux 5.13+. Use `LANDLOCK_ABI_VERSION` discovery to handle older kernels gracefully.

```rust
let ruleset = Ruleset::new()
    .handle_access(AccessFs::from_all(abi))?
    .create()?;

for path in &manifest.filesystem.read {
    ruleset = ruleset.add_rule(PathBeneath::new(
        PathFd::new(path)?,
        AccessFs::from_read(abi),
    ))?;
}

for path in &manifest.filesystem.write {
    ruleset = ruleset.add_rule(PathBeneath::new(
        PathFd::new(path)?,
        AccessFs::from_all(abi),
    ))?;
}

ruleset.restrict_self()?;
```

#### 9.2.5 Distro support matrix

| Distro | Min version | Status | Notes |
|---|---|---|---|
| Ubuntu | 22.04 | tier 1 | userns unprivileged enabled |
| Ubuntu | 24.04 | tier 1 | |
| Debian | 12 | tier 1 | |
| Fedora | 38 | tier 1 | |
| Arch | rolling | tier 1 | |
| NixOS | 23.05 | tier 2 | needs `security.unprivilegedUsernsClone = true` |
| Alpine | 3.18 | tier 2 | needs sysctl tweak |
| RHEL | 9 | tier 2 | userns may need enabling |

Tier 1: tested in CI, fully supported. Tier 2: documented setup, community-supported.

Daemon performs capability probe on startup; refuses to start with actionable error message if requirements unmet.

### 9.3 macOS backend — full specification

#### 9.3.1 Spawn sequence

1. Validate macOS version (≥13.0).
2. Allocate sandbox UUID.
3. Allocate UID from pool (`_hatch_001`–`_hatch_064`).
4. Generate sandbox-exec profile at `$TMPDIR/hatch/<uuid>.sb`.
5. Generate PF anchor rules; load via `pfctl -a hatch/<uuid> -f -`.
6. Create per-server runtime dir at `$TMPDIR/hatch/<uuid>/`.
7. `fork()`. Child:
    - `setuid()` to allocated UID.
    - Set up environment per manifest.
    - `setrlimit` for memory, CPU, nofile, nproc.
    - `execve("/usr/bin/sandbox-exec", ["-f", profile_path, "--", program, args...])`.
8. Parent: record pid, monitor with `kqueue`.

On exit:
- Tear down PF anchor.
- Release UID back to pool.
- Remove runtime dir.

#### 9.3.2 sandbox-exec profile template

```scheme
(version 1)
(deny default)

;; Basic process operations
(allow process-fork)
(allow process-info-pidinfo (target self))
(allow signal (target self))

;; Stdio
(allow file-read-data file-write-data
       (literal "/dev/stdin")
       (literal "/dev/stdout")
       (literal "/dev/stderr")
       (literal "/dev/null")
       (literal "/dev/urandom")
       (literal "/dev/random"))

;; System libraries and frameworks (required for any executable to run)
(allow file-read* file-read-metadata
       (subpath "/usr/lib")
       (subpath "/usr/share")
       (subpath "/System/Library")
       (subpath "/Library/Frameworks")
       (subpath "/private/etc/ssl"))

;; Sysctls needed for runtime
(allow sysctl-read)

;; Minimum mach lookups
(allow mach-lookup
       (global-name "com.apple.system.notification_center")
       (global-name "com.apple.system.logger"))

;; Per-manifest filesystem rules
;; <generated: for path in manifest.filesystem.read>
(allow file-read* file-read-metadata (subpath "<resolved-path>"))
;; <for path in manifest.filesystem.write>
(allow file-read* file-write* (subpath "<resolved-path>"))

;; Runtime scratch
(allow file-read* file-write* (subpath "<HATCH_RUNTIME_DIR>"))

;; Network — only to the proxy
(allow network-outbound (remote tcp "127.0.0.1:<PROXY_PORT>"))
(allow network-outbound (remote udp "127.0.0.1:<DNS_PORT>"))

;; Subprocess (gated on manifest.exec.allow_subprocess)
;; <if allowed:>
(allow process-exec
       (literal "<binary-path>")
       ...)

;; Manifest-supplied extra rules
;; <append manifest.platform.macos.extra_sbpl verbatim>
```

#### 9.3.3 PF rules per sandbox UID

Loaded into a per-sandbox anchor `hatch/<uuid>`:

```
# Allow only to the proxy and DNS resolver, originating from this UID
table <hatch_proxy_127001> persist { 127.0.0.1 }
pass out quick proto tcp from any to <hatch_proxy_127001> port <PROXY_PORT> user _hatch_001 keep state
pass out quick proto udp from any to <hatch_proxy_127001> port <DNS_PORT>   user _hatch_001 keep state
block drop out quick from any user _hatch_001
```

Loaded with `pfctl -a hatch/<uuid> -f <file>`. Cleared on server exit with `pfctl -a hatch/<uuid> -F all`.

PF enabled on the system at daemon install time if not already (`pfctl -e`); the daemon's anchor coexists with any existing PF config.

#### 9.3.4 UID pool installer

Run once at daemon install via `sudo hatch install --system`. Creates service accounts:

```bash
for i in $(seq -f "%03g" 1 64); do
    user="_hatch_${i}"
    dscl . -create "/Users/${user}"
    dscl . -create "/Users/${user}" UserShell /usr/bin/false
    dscl . -create "/Users/${user}" NFSHomeDirectory /var/empty
    dscl . -create "/Users/${user}" UniqueID $((300 + i))
    dscl . -create "/Users/${user}" PrimaryGroupID 300
    dscl . -create "/Users/${user}" RealName "Hatch Sandbox ${i}"
    dscl . -create "/Users/${user}" Password "*"
    dscl . -append "/Groups/_hatch" GroupMembership "${user}"
done
```

UID range 300–363 is reserved by macOS for system service accounts.

#### 9.3.5 Endpoint Security path (optional)

Gated behind compile-time feature flag `endpoint-security`. Requires:
- Apple Developer ID.
- ES client entitlement (`com.apple.developer.endpoint-security.client`).
- System Extension installation by the user.

When available, the entitled daemon subscribes to:
- `ES_EVENT_TYPE_AUTH_EXEC` — vet execve in addition to sandbox-exec.
- `ES_EVENT_TYPE_AUTH_OPEN` — defense-in-depth file access checks.
- `ES_EVENT_TYPE_AUTH_CONNECT` — connect-time network checks (redundant with PF but gives audit-grade visibility).

Without entitlement: ES path is compiled out; daemon uses default path.

#### 9.3.6 Code signing and notarization

Required for distribution. Apple Developer ID Application certificate.

Build process:
1. `cargo build --release --target x86_64-apple-darwin`
2. `cargo build --release --target aarch64-apple-darwin`
3. `lipo -create -output hatch-universal target/x86_64-apple-darwin/release/hatch target/aarch64-apple-darwin/release/hatch`
4. Repeat for `hatch-daemon`, `hatch-shim`.
5. Sign each binary:
   ```
   codesign --force --options runtime --timestamp \
            --sign "Developer ID Application: <name> (<TEAMID>)" \
            --entitlements entitlements.plist \
            <binary>
   ```
6. Build `.pkg` installer with `pkgbuild` + `productbuild`.
7. Sign the pkg: `productsign --sign "Developer ID Installer: ..." <pkg> <signed-pkg>`.
8. Notarize: `xcrun notarytool submit <signed-pkg> --wait --keychain-profile <profile>`.
9. Staple: `xcrun stapler staple <signed-pkg>`.

`entitlements.plist`:
```xml
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-jit</key><false/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key><false/>
    <key>com.apple.security.cs.disable-library-validation</key><false/>
    <!-- Only on the entitled-daemon variant: -->
    <!-- <key>com.apple.developer.endpoint-security.client</key><true/> -->
</dict>
</plist>
```

#### 9.3.7 launchd integration

LaunchAgent at `~/Library/LaunchAgents/sh.hatch.daemon.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>sh.hatch.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/hatch-daemon</string>
        <string>--launchd</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/>
        <key>Crashed</key><true/>
    </dict>
    <key>ThrottleInterval</key><integer>10</integer>
    <key>StandardOutPath</key>
    <string>/Users/USERNAME/Library/Logs/hatch/daemon.out.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/USERNAME/Library/Logs/hatch/daemon.err.log</string>
    <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
```

#### 9.3.8 macOS version support

- macOS 13 (Ventura): tier 1.
- macOS 14 (Sonoma): tier 1.
- macOS 15 (Sequoia): tier 1.

Test suite runs on all three in CI.

### 9.4 Systemd integration (Linux)

User service at `~/.config/systemd/user/hatch-daemon.service`:

```ini
[Unit]
Description=Hatch daemon
After=default.target

[Service]
ExecStart=%h/.local/bin/hatch-daemon --systemd
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%t/hatch %h/.local/state/hatch %h/.cache/hatch
PrivateTmp=true

[Install]
WantedBy=default.target
```

Enabled via `systemctl --user enable --now hatch-daemon`.


---

## 10. Layer 3 — Policy engine

### 10.1 Components

| Component | Crate | Responsibility |
|---|---|---|
| Manifest parser | `hatch-core::manifest` | TOML → typed struct |
| Manifest validator | `hatch-core::validate` | Schema + semantic checks, risk scoring |
| Policy compiler | `hatch-core::compile` | Manifest → `CompiledPolicy` |
| Backend codegen | `hatch-sandbox-{linux,macos}` | `CompiledPolicy` → platform primitives |
| Signature verifier | `hatch-core::sig` | ed25519 signature check against trust store |
| Observation mode | `hatch-cli::observe` | Trace → candidate manifest |

### 10.2 Core types

```rust
// crates/hatch-core/src/manifest.rs

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    pub schema_version: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub homepage: Option<String>,
    pub license: Option<String>,
    pub command: CommandSpec,
    pub integrity: Option<IntegritySpec>,
    pub network: NetworkPolicy,
    pub filesystem: FilesystemPolicy,
    pub env: EnvPolicy,
    pub exec: ExecPolicy,
    pub resources: ResourceLimits,
    pub tool_policy: ToolPolicy,
    pub platform: PlatformOverrides,
    pub signature: Option<Signature>,
}

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub manifest: Manifest,
    pub resolved_paths_read: Vec<PathBuf>,
    pub resolved_paths_write: Vec<PathBuf>,
    pub resolved_env: BTreeMap<String, String>,
    pub network_allow: NetworkAllowSet,
    pub tool_rules: Vec<CompiledToolRule>,
    pub response_filters: Vec<CompiledRegex>,
    pub risk_score: u32,
}

pub struct CompiledToolRule {
    pub tool_pattern: glob::Pattern,
    pub when: Option<cel_interpreter::Program>,  // pre-parsed CEL
    pub action: RuleAction,
}

pub enum RuleAction { Allow, Deny, RequireApproval }
```

### 10.3 Compilation pipeline

```
Manifest (TOML) 
   │
   ▼  parse (toml::from_str)
typed Manifest
   │
   ▼  validate (schema + semantic + risk score)
ValidatedManifest
   │
   ▼  resolve_templates (substitute $HOME, $PROJECT_ROOT, etc.)
ResolvedManifest
   │
   ▼  compile (parse CEL, compile regex, build allowlists)
CompiledPolicy
   │
   ▼  backend_codegen
Linux:  BwrapArgs + SeccompFilter + CgroupsConfig + NetnsPlan
macOS:  SbplProfile + PfRules + SetrlimitValues + UidAssignment
```

Cached at the `CompiledPolicy` stage in SQLite, keyed by manifest fingerprint (BLAKE3 of canonicalized manifest).

### 10.4 CEL expression context

Available identifiers in `tool_policy.rules.when`:

| Identifier | Type | Meaning |
|---|---|---|
| `tool` | string | Tool name |
| `args` | map<string, dyn> | Tool call arguments |
| `server` | string | Server name |
| `now` | timestamp | Current time |
| `caller` | string | Calling host name (e.g., "claude-desktop") |

CEL stdlib enabled: string functions, list/map operations, timestamp arithmetic. Side-effecting and recursive constructs disabled. Evaluation timeout: 50 ms.

### 10.5 Observation mode

**Linux:** ptrace-based tracer in `hatch-cli observe`. Attaches to the spawned server with `PTRACE_SEIZE`. Intercepts: `openat`, `connect`, `execve`, `bind`. Records normalized paths and destinations. Outputs candidate manifest after process exits.

Alternative: eBPF using `aya`. Lower overhead, requires CAP_BPF or root. Both implementations provided; CLI picks based on capability check.

**macOS:** dtrace-based tracer. Requires SIP partial disable for non-Apple binaries, or notarized dtrace helper. Document the tradeoff clearly. Records syscalls via `syscall:::entry` probes filtered to the target pid.

**Manifest synthesis:**

1. Aggregate raw access list.
2. Normalize paths (resolve symlinks, collapse `/usr/lib/python3.*/site-packages/<pkg>/*` into `/usr/lib/python3.*/site-packages`).
3. Group network destinations by hostname (resolve IPs back via DNS history).
4. Detect read-only vs read-write access.
5. Detect subprocess executions.
6. Emit candidate manifest with conservative defaults.
7. Mark generated fields with `# observed:` comments so the user knows what came from tracing.

The user reviews, edits, and commits.

### 10.6 Signature trust store

Bundled with each hatch release. Located at `/etc/hatch/trust/` (system install) or `$XDG_CONFIG_HOME/hatch/trust/` (user install).

Structure:

```
trust/
├── policy.toml                     # trust policy
├── active/
│   └── hatch-registry-2026.pub     # ed25519 public key
└── revoked/
    └── hatch-registry-2025.pub
```

`policy.toml`:

```toml
trust_unsigned = false
trust_local = true                  # local manifests authored by user
max_signature_age_days = 730

[[allowed_signers]]
key_id = "hatch-registry-2026"
algorithm = "ed25519"
public_key = "base64..."
```

Updates via `hatch registry update` fetch a new signed `policy.toml` from the registry, signed by the previous active key.

---

## 11. Layer 4 — Protocol mediation

### 11.1 Shim architecture

The shim is the per-server entry point. Tiny binary (target: under 5 MB). Single responsibility: bridge between the MCP host and the daemon-managed sandboxed server, with JSON-RPC interception.

```rust
// crates/hatch-shim/src/main.rs (sketch)

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let server_name = env::var("HATCH_SERVER")?;
    let daemon = connect_daemon().await?;

    // Request the daemon spawn the server for us
    let session = daemon.spawn_server(&server_name).await?;
    // session contains: server_stdin_fd, server_stdout_fd, policy_socket

    // Pump stdio with interception
    let host_in  = tokio::io::stdin();
    let host_out = tokio::io::stdout();

    let host_to_server = pump_with_interception(
        host_in, session.server_stdin, &session.policy_socket, Direction::Request);
    let server_to_host = pump_with_interception(
        session.server_stdout, host_out, &session.policy_socket, Direction::Response);

    tokio::try_join!(host_to_server, server_to_host)?;
    Ok(())
}
```

### 11.2 JSON-RPC interception

The shim reads stdio framed by newlines (MCP convention) or by `Content-Length` headers (LSP-style fallback). For each message:

1. Parse with `simd-json::from_slice` into a borrowed value.
2. Inspect `method`:
   - `tools/list`: forward, then cache the returned tool schemas for argument validation.
   - `tools/call`: extract `name` and `arguments`; consult daemon policy.
   - other methods: forward verbatim.
3. For tool calls: send `PolicyQuery` over the policy socket; wait for `PolicyDecision`.
4. Based on decision: forward, deny, or hold for approval.

**Latency budget:**

- Median tool-call overhead from shim interception: ≤2 ms.
- Approval-gated tool calls: variable (depends on user response).

Achieved by:
- Keeping the shim single-threaded with `tokio` current-thread runtime.
- Local unix socket to daemon.
- Pre-compiled CEL programs in `CompiledPolicy`.
- Zero-copy where possible for non-intercepted messages (just relay bytes).

### 11.3 Approval flow

When a tool call matches a `require_approval` rule:

1. Shim sends `PolicyQuery::ToolCall { tool, args }` to daemon.
2. Daemon evaluates rules; result is `RequireApproval { approval_id }`.
3. Daemon inserts `approvals` row, status `pending`.
4. Daemon emits system notification:
   - **Linux:** D-Bus call to `org.freedesktop.Notifications`. Uses `desktop_actions` for inline Approve/Deny buttons where supported. Falls back to `hatch approve <id>` CLI.
   - **macOS:** spawn helper app `Hatch Approval.app` (Swift, signed) which presents `NSUserNotification`/`UNUserNotification` with action buttons. Helper writes decision to daemon socket.
5. Concurrently logs `approval_requested` audit event.
6. User clicks Approve or Deny; helper or D-Bus callback notifies daemon.
7. Daemon updates `approvals` row; sends `PolicyDecision` to shim.
8. Shim forwards or denies the tool call.

**Timeout:** Configurable default 60s. On timeout: deny + audit.

**Session memory:** Approval dialogs offer "Remember for this session" (until daemon restart) and "Remember for this manifest version" (persistent). Stored in `approvals.remembered_until`.

### 11.4 Argument inspection (CEL)

Manifest rules:

```toml
[[tool_policy.rules]]
tool = "filesystem.write"
when = "args.path.startsWith('/etc/') || args.path.startsWith('/sys/')"
action = "deny"

[[tool_policy.rules]]
tool = "shell.exec"
when = "args.command.matches('(rm|dd|mkfs|shutdown)')"
action = "require_approval"

[[tool_policy.rules]]
tool = "*"
when = "args.size_bytes > 1048576"
action = "require_approval"
```

Compiled once at manifest install, evaluated against each tool call. CEL is fast and side-effect-free.

### 11.5 Response filtering

Applied to the `content` field of `tools/call` responses before forwarding to host.

Default patterns (compiled into hatch, included unless manifest opts out):

| Pattern label | Regex |
|---|---|
| AWS access key | `AKIA[0-9A-Z]{16}` |
| AWS secret key | `(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}` |
| GitHub PAT | `gh[pousr]_[A-Za-z0-9]{36,255}` |
| Slack token | `xox[bpsa]-[A-Za-z0-9-]+` |
| Stripe key | `sk_live_[A-Za-z0-9]{24,}` |
| Generic API key | `(?i)(api[_-]?key|secret|token)["\s:=]+[A-Za-z0-9._\-]{16,}` |
| Private key block | `-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----` |
| JWT | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` |

Manifests can append patterns or disable defaults.

### 11.6 Policy query protocol (shim ↔ daemon)

Framed by length-prefixed JSON over unix socket.

```rust
// crates/hatch-ipc/src/lib.rs

#[derive(Serialize, Deserialize)]
pub enum PolicyQuery {
    SpawnServer { name: String, host: String },
    ToolCall { server_id: String, tool: String, args: serde_json::Value },
    ResponseFilter { server_id: String, response: serde_json::Value },
    Heartbeat,
}

#[derive(Serialize, Deserialize)]
pub enum PolicyDecision {
    SpawnReady { server_id: String, server_stdin: RawFd, server_stdout: RawFd },
    Allow,
    Deny { reason: String },
    RequireApproval { approval_id: String, timeout_seconds: u32 },
    FilteredResponse { response: serde_json::Value, redactions: u32 },
    Heartbeat,
}
```

FDs are passed via `SCM_RIGHTS`.

---

## 12. Layer 5 — User interface

### 12.1 CLI surface (complete)

```
USAGE: hatch <COMMAND>

Top-level:
    hatch                           Show status overview
    hatch help [command]            Help
    hatch version                   Version info
    hatch doctor                    Diagnose installation issues

Installation:
    hatch install <name[@version]>          Install from registry
    hatch install --file <path>             Install from local manifest
    hatch install --git <url> [--ref <ref>] Install from git
    hatch install --allow-unsigned          Permit unsigned manifests (warns)
    hatch uninstall <name>                  Remove a manifest
    hatch list                              Installed manifests
    hatch list --running                    Currently sandboxed servers

Manifest tools:
    hatch manifest show <name>              Print manifest
    hatch manifest validate <path>          Validate without installing
    hatch manifest explain <path-or-name>   Human-readable summary + risk score
    hatch manifest diff <name> <path>       Compare installed vs file
    hatch manifest edit <name>              Open in $EDITOR

Observation mode:
    hatch observe -- <command...>           Run unsandboxed, trace, output manifest
    hatch observe --output <path> -- <command...>

Running servers:
    hatch run <name>                        Manual spawn (for testing/debugging)
    hatch stop <name|server-id>             Stop a running server
    hatch ps                                Like docker ps
    hatch logs <name|server-id> [--follow]  Server stderr
    hatch inspect <name|server-id>          Sandbox details for a running server

Audit:
    hatch audit                             Recent events (default last 100)
    hatch audit --follow                    Stream live
    hatch audit --tui                       Full TUI viewer
    hatch audit --server <name>             Filter
    hatch audit --since <duration>          Time filter (1h, 1d, ...)
    hatch audit --event <type>              Event type filter
    hatch audit export <path>               Export to file

Host integration:
    hatch config status                     Which host configs are wrapped
    hatch config sync                       Rewrite all configs to use shim
    hatch config sync --host <name>         Specific host only
    hatch config unsync                     Restore original host configs
    hatch config show <host>                Show effective config

Registry:
    hatch registry update                   Refresh manifest cache
    hatch registry search <query>           Search available
    hatch registry info <name>              Manifest details
    hatch registry list                     All available manifests
    hatch registry verify <name>            Verify signature

Daemon:
    hatch daemon start                      Start daemon (manual)
    hatch daemon stop                       Stop daemon
    hatch daemon restart                    Restart
    hatch daemon status                     Health check
    hatch daemon logs [--follow]            Daemon logs

Approval:
    hatch approve <approval-id>             Approve a pending request
    hatch approve --list                    List pending
    hatch deny <approval-id>                Deny

Debugging:
    hatch debug --server <name>             Verbose sandbox info
    hatch debug --capture-args <name>       Log full args for a server (opt-in)
    hatch debug profile <name>              Generate platform profile for a manifest
```

Each command implemented in `crates/hatch-cli/src/commands/`. Standard exit codes:
- 0: success
- 1: generic error
- 2: usage error
- 10: daemon not reachable
- 11: server not found
- 12: manifest validation error
- 13: signature verification failed
- 14: approval timeout
- 15: sandbox spawn failed

### 12.2 Output format

Default: human-friendly, color-aware (auto-detect TTY).

Global flag `--format <text|json|jsonl>` switches output.

Commands that produce structured data (list, ps, inspect, audit) emit JSON when piped or when `--format json` is set.

### 12.3 TUI audit viewer

`hatch audit --tui` opens a full-screen ratatui interface.

Layout:

```
┌─ hatch audit ───────────────────────────────── 4 running ─ 1 pending ─┐
│ Servers                  │ Events                                     │
│ ─────────                │ ──────                                     │
│ ▶ github       running   │ 10:30:45 github   tool_call create_issue   │
│   linear       running   │ 10:30:46 github   net_attempt api.github   │
│   filesystem   running   │ 10:30:47 linear   tool_call list_issues    │
│   slack        running   │ 10:30:50 slack    fs_denied  ~/.aws/cred   │
│                          │ ...                                        │
│                          │                                            │
├──────────────────────────┴────────────────────────────────────────────┤
│ Detail                                                                │
│ ──────                                                                │
│ Server:   github                                                      │
│ Tool:     create_issue                                                │
│ Args:     {"repo": "user/repo", "title": "[redacted-42-chars]"}       │
│ Decision: allow                                                       │
│ Latency:  230 ms                                                      │
└─ q quit  /search  f filter  p pause  e export ────────────────────────┘
```

Hotkeys: arrows navigate, `/` search, `f` filter, `p` pause stream, `e` export selection, `a` approve pending, `d` deny pending, `q` quit.

### 12.4 Approval helper apps

**Linux:** No separate binary needed. Uses D-Bus `org.freedesktop.Notifications` with action buttons. Most modern desktops support this (GNOME, KDE, sway+mako, etc.). Fallback: print approval URL to terminal of any open `hatch audit --tui` instance and emit a desktop bell.

**macOS:** Separate small SwiftUI app bundled inside the pkg, installed at `/Applications/Hatch Approval.app`. Launched on demand by the daemon. Uses `UNUserNotificationCenter` for system notifications with action buttons. Requires Notifications permission (prompt on first use).

---

## 13. Daemon IPC protocol

### 13.1 Transport

Unix domain socket. Stream-oriented. Length-prefixed framing:

```
[4 bytes BE: length N] [N bytes: JSON payload]
```

FDs are transferred out-of-band via `SCM_RIGHTS`.

### 13.2 Authentication

Socket file permissions: 0600, owned by user. The daemon trusts any process connecting as the same UID. No additional auth.

For shim ↔ daemon: shim sends its PID; daemon verifies via `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` (macOS) that the connection comes from the expected UID.

### 13.3 Message types

```rust
// crates/hatch-ipc/src/messages.rs

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientRequest {
    // From CLI:
    Install { source: InstallSource },
    Uninstall { name: String },
    ListManifests,
    ListRunning,
    SpawnManual { name: String },
    Stop { server_id: String },
    Inspect { server_id: String },
    Audit { filter: AuditFilter, follow: bool },
    Approve { approval_id: String, remember: RememberMode },
    Deny { approval_id: String },
    ConfigSync { host: Option<String> },
    ConfigUnsync,
    RegistryUpdate,
    DaemonStatus,
    DaemonStop,

    // From shim:
    SpawnSandboxed { manifest_name: String, host: String },
    PolicyQuery { server_id: String, query: PolicyQuery },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DaemonResponse {
    Ok,
    Error { code: ErrorCode, message: String },
    Manifests { items: Vec<ManifestSummary> },
    RunningServers { items: Vec<RunningServerSummary> },
    Spawned { server_id: String, stdin_fd_passed: bool, stdout_fd_passed: bool },
    AuditEvents { events: Vec<AuditEvent> },
    PolicyDecision { decision: PolicyDecision },
    DaemonStatus { uptime_seconds: u64, running_servers: usize, version: String },
}
```

### 13.4 FD passing for sandboxed server stdio

When the shim sends `SpawnSandboxed`, the daemon:

1. Compiles the manifest.
2. Creates two `socketpair`s.
3. Spawns the sandboxed server (via Layer 2 backend) with one end of each pair as stdin/stdout.
4. Sends the other ends back to the shim via `SCM_RIGHTS`.
5. Replies `Spawned`.

The shim then has direct FDs to the sandboxed server's stdio.

---

## 14. Host integration

### 14.1 Supported hosts (1.0)

| Host | Config location (macOS) | Config location (Linux) | Format |
|---|---|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | JSON |
| Cursor | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` | JSON |
| Claude Code | `~/.claude/settings.json` + `.claude/settings.json` (per-project) | same | JSON |
| Zed | `~/.config/zed/settings.json` | `~/.config/zed/settings.json` | JSON |
| Continue | `~/.continue/config.json` | `~/.continue/config.json` | JSON |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | same | JSON |

### 14.2 Rewrite algorithm

On `hatch config sync`:

1. For each known host config path that exists:
   a. Read the file.
   b. If a top-level `_hatch` metadata field exists, the config is already wrapped — skip with warning unless `--force`.
   c. Write a backup at `<path>.hatch-backup-<UTC-timestamp>`.
   d. For each `mcpServers` entry (the field name varies by host):
      - Capture the original `command` and `args`.
      - Replace with shim invocation:
        ```json
        {
          "command": "/usr/local/bin/hatch-shim",
          "args": [],
          "env": {
            "HATCH_SERVER": "<original-name>"
          }
        }
        ```
      - The original command/args are not embedded in the rewritten config; they come from the installed manifest. This is intentional — it forces the user to install the manifest before the server can run.
   e. Add a top-level `_hatch` field:
      ```json
      "_hatch": {
        "version": "1.0.0",
        "wrapped_at": "2026-05-13T10:30:00Z",
        "original_servers": { "<name>": { "command": "...", "args": [...] } }
      }
      ```
2. Audit: emit a `config_sync` event for each host.

On `hatch config unsync`:

1. For each wrapped config:
   a. Use `_hatch.original_servers` to restore each entry.
   b. Remove the `_hatch` field.
   c. Verify byte-for-byte that the result equals the most recent `.hatch-backup-*` file. If not, abort and tell the user to restore manually from backup.

### 14.3 Per-host quirks

**Claude Desktop** — restarts required after config change. Daemon emits a notification telling the user.

**Cursor** — supports per-workspace MCP servers in `.cursor/mcp.json` in addition to user-level. `hatch config sync --workspace` rewrites the current directory's config.

**Claude Code** — settings.json may not exist by default. Create it if needed. Also handles `.mcp.json` in project root for project-level servers.

**Zed** — MCP config is nested inside the broader `settings.json`; only the `context_servers` subtree is touched.

---

## 15. Manifest registry

Separate repo `malwarebo/manifests`. Treated as its own product.

### 15.1 Contribution flow

1. Contributor runs `hatch observe -- <server-command>` against a real workload.
2. Hand-edits the candidate manifest in `servers/<name>/manifest.toml`.
3. Writes `servers/<name>/README.md` (what the server does, why these permissions, known issues).
4. Writes `servers/<name>/test/smoke.sh` (a minimal script that exercises the server's primary tool).
5. Opens a PR.
6. CI runs:
   - Schema validation against `schema/manifest.schema.json`.
   - Semantic checks via `hatch manifest validate`.
   - Risk score reported as PR comment.
   - Smoke test: installs the proposed manifest in a CI sandbox (a hatch instance), runs `test/smoke.sh`, asserts on `test/expected.json`.
   - Diff against previous version (if updating): risk score delta, permission delta.
7. Maintainer review focused on:
   - Are network destinations minimal?
   - Are filesystem write paths necessary and bounded?
   - Is `allow_subprocess` justified?
   - Does the risk score match the actual capability needs?
8. Merge → CI signs the manifest → adds to next release bundle.

### 15.2 Release process

Releases tagged with date format: `v2026.05.13`. On tag:

1. CI builds bundle: `manifests-<date>.tar.zst` containing all signed manifests + a `manifest-index.json`.
2. Bundle is signed by the active delegated key (held in CI as a GitHub Actions secret encrypted to the CI signer's age key).
3. Master key (offline, on hardware token) signs the delegated key on rotation, not per release.
4. Published to GitHub Releases with `.sig` file.
5. Daemon `hatch registry update` fetches latest release, verifies signature against bundled trust store, unpacks to cache.

### 15.3 Key management

- **Master key:** ed25519, generated offline, stored on Yubikey or equivalent. Used only to sign delegated keys. Rotation: every 5 years.
- **Delegated CI signing key:** ed25519, lives encrypted in CI secret. Rotation: every 6 months. Signed by master.
- **Trust store distribution:** Each hatch release bundles the current master pubkey + last 2 delegated pubkeys. Daemon refuses signatures from non-bundled keys.
- **Revocation:** Revoked keys go in `signing/revoked/`. New hatch releases include revocation list.

### 15.4 Initial manifest set (target: 20 at 1.0)

Author all before 1.0:

1. `filesystem`
2. `github`
3. `git`
4. `postgres`
5. `sqlite`
6. `puppeteer`
7. `playwright`
8. `linear`
9. `slack`
10. `google-drive`
11. `fetch`
12. `time`
13. `memory`
14. `sequentialthinking`
15. `everything`
16. `notion`
17. `jira`
18. `figma`
19. `sentry`
20. `kubernetes`

Each in `servers/<name>/` with manifest, README, CHANGELOG, smoke test.

### 15.5 Registry browser

Static site at `manifests.hatch.sh`. Generated from the repo. Each manifest gets a page showing:

- Description and version.
- Risk score with breakdown.
- Network destinations.
- Filesystem paths.
- Tool policy rules.
- Install command (`hatch install <name>`).
- Source link to the manifest file.

Built with Astro or Zola from the registry repo's content. CI regenerates on each merge.

---

## 16. Documentation site

`docs.hatch.sh`. Built with mdBook (Rust-native, fast, no JS framework churn).

### 16.1 Site structure

```
Home
├── Quick Start                     (5-minute install + first sandboxed server)
├── Concepts
│   ├── What hatch protects against
│   ├── Threat model                (the most-read page)
│   ├── How the sandbox works
│   ├── Manifests explained
│   └── Per-platform guarantees
├── Guide
│   ├── Installation (Linux)
│   ├── Installation (macOS)
│   ├── Wrapping your first MCP server
│   ├── Authoring a manifest
│   ├── Observation mode walkthrough
│   ├── Approval flows
│   ├── Tool-policy DSL reference
│   ├── Integration: Claude Desktop
│   ├── Integration: Cursor
│   ├── Integration: Claude Code
│   ├── Integration: Zed
│   ├── Troubleshooting
│   └── FAQ
├── Reference
│   ├── Manifest schema (complete)
│   ├── CLI commands (every flag)
│   ├── Audit log schema
│   ├── Metrics
│   ├── Configuration files
│   ├── Environment variables
│   └── Exit codes
├── Security
│   ├── Threat model (detailed)
│   ├── What hatch does NOT protect against
│   ├── Vulnerability disclosure
│   ├── Past advisories
│   ├── Signing & verification
│   └── Audit log forensics guide
├── Manifests Registry
│   ├── Browsing the registry
│   ├── Contributing a manifest
│   ├── Manifest review checklist
│   └── Signing process
├── Architecture
│   ├── Overview
│   ├── Layer breakdown
│   ├── Linux backend
│   ├── macOS backend
│   ├── Egress proxy
│   ├── Protocol mediation
│   └── Daemon internals
└── Project
    ├── Roadmap
    ├── Changelog
    ├── Contributing
    ├── Code of conduct
    └── License
```

### 16.2 Threat-model page priorities

Write this page **before any code**. It forces articulation. Sections:

1. Assets being protected (from §2.1).
2. Adversaries (from §2.2).
3. Trust assumptions (from §2.3).
4. What hatch protects against (from §2.4) — each item with a concrete scenario.
5. What hatch does NOT protect against (from §2.5) — each item with a concrete scenario.
6. Per-platform guarantee table (from §2.6).
7. Trust boundary diagram.

This page is the contract. When users ask "does hatch protect against X," the answer comes from here.


---

## 17. Build sequence

You said no public v1/v2. This is internal milestone sequence; public release is 1.0 at the end. The order is chosen so that an end-to-end vertical slice exists by month 2, then each phase deepens one layer at a time without breaking lower layers.

### Phase A — Foundation (weeks 1–4)

**Goal:** Cargo workspace compiles. CI green on Linux + macOS. Daemon, CLI, shim can talk to each other. Audit log works. Egress proxy works in isolation. Sandbox backends are stubs.

Deliverables:
- Workspace skeleton with all crates (empty stubs OK).
- CI: rustfmt, clippy, build, test on both platforms.
- `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `README.md`.
- Threat model page written in docs.
- Manifest schema spec written in docs.
- Layer 0: audit log (JSONL writer), SQLite schema + migrations.
- Layer 1: SNI proxy + DNS resolver, tested against a real HTTPS server in isolation.
- IPC: unix socket protocol between CLI/shim/daemon, message types defined.
- Stub sandbox backend: `exec`s the server with no isolation, but full pipeline works.
- Minimal CLI: `hatch run`, `hatch ps`, `hatch audit`.
- End-to-end smoke: daemon launches a server via stub sandbox, shim pumps stdio, audit logs spawn/exit.

### Phase B — Linux backend (weeks 5–12)

**Goal:** Full Linux isolation. A real MCP server runs sandboxed with network restricted, filesystem restricted, syscalls filtered.

Deliverables:
- Manifest parser + validator.
- Policy compiler for Linux.
- bwrap-equivalent spawn via direct syscalls.
- Mount namespace construction.
- Seccomp filter compilation and loading.
- Landlock defense-in-depth.
- cgroups v2 integration.
- netns + veth + iptables wiring.
- Egress proxy wired into netns.
- `filesystem` MCP server running sandboxed end-to-end.
- `github` MCP server running sandboxed end-to-end.
- Malicious-server demo: a test server that tries to read `~/.ssh/id_rsa` and POST it to an attacker host. Verify hatch blocks both.
- Distro testing: Ubuntu 22.04/24.04, Debian 12, Fedora 39.

### Phase C — macOS backend (weeks 13–20)

**Goal:** Full macOS isolation. Same servers running sandboxed with strong filesystem and network enforcement.

Deliverables:
- Apple Developer enrollment, code signing infrastructure.
- UID pool installer (`sudo hatch install --system`).
- sandbox-exec profile generator.
- PF rules generator and loader.
- Egress proxy wired via PF redirect.
- launchd plist generation.
- Notarization pipeline in CI.
- Same servers running sandboxed on macOS as on Linux.
- Malicious-server demo working on macOS.
- macOS 13/14/15 tested.
- Begin Endpoint Security entitlement application (multi-month process; start early).

### Phase D — Observation mode (weeks 21–24)

**Goal:** Users can run a new server unsandboxed-but-traced and get a candidate manifest auto-generated.

Deliverables:
- Linux: ptrace tracer in `hatch-cli observe`.
- Optional Linux: eBPF tracer via `aya` (better performance).
- macOS: dtrace tracer. SIP-requirement documented.
- Manifest synthesizer: trace → normalized manifest with `# observed:` comments.
- End-to-end: observe a real server, get a manifest, install it, run sandboxed, server still works.

### Phase E — Protocol mediation (weeks 25–32)

**Goal:** Tool calls intercepted, policy-checked, optionally approved, logged. Response filtering works.

Deliverables:
- JSON-RPC parser in shim hot path (simd-json).
- Tool-call interception with sub-2ms median overhead.
- CEL integration for argument rules.
- Default secret-pattern response filters.
- Approval system: D-Bus notifications on Linux, Swift helper app on macOS.
- Session memory for approvals.
- TUI audit viewer (`ratatui`).

### Phase F — Host integration (weeks 33–36)

**Goal:** One command wraps a user's existing MCP setup. Reversible.

Deliverables:
- Config rewriter for Claude Desktop, Cursor, Claude Code, Zed, Continue, Windsurf.
- Backup/restore logic with byte-equality verification.
- `hatch config sync`/`unsync`/`status`.
- Per-host quirk handling.
- Idempotency for already-wrapped configs.

### Phase G — Registry and manifest set (weeks 37–44)

**Goal:** Public manifest registry stood up with 20 manifests authored. Daemon fetches signed updates.

Deliverables:
- `malwarebo/manifests` repo with structure, schema, CI.
- Signing infrastructure: offline master key, delegated CI key.
- All 20 initial manifests authored, tested, signed.
- README per server explaining permissions.
- Smoke tests for each manifest in CI.
- Registry client in daemon: fetch, verify, cache, update.
- Static registry browser at `manifests.hatch.sh`.

### Phase H — Hardening (weeks 45–52)

**Goal:** Production-ready. Security audit done. Fuzzing in CI. Stress tested. Docs complete.

Deliverables:
- Fuzz the manifest parser (cargo-fuzz, run 1M+ iterations).
- Fuzz the JSON-RPC shim parser.
- Fuzz the policy compiler.
- Stress test: 50 servers sandboxed simultaneously.
- Daemon crash recovery: `kill -9` daemon, verify cleanup on restart.
- Security audit: paid (Trail of Bits / Cure53 / NCC Group — $30–80k) or community-funded.
- Address all audit findings.
- Documentation pass: every CLI flag, every config option, every error message.
- Vulnerability disclosure setup: GitHub Security Advisories, `security@hatch.sh`, PGP key.

### Phase I — 1.0 release (weeks 53–56)

**Goal:** Public launch.

Deliverables:
- Tag 1.0 across both repos.
- Signed release artifacts: `.tar.gz` for Linux (x86_64, aarch64); `.pkg` for macOS (signed, notarized, stapled).
- Homebrew tap (`malwarebo/tap`).
- AUR package.
- Nix flake.
- Launch post: threat model summary, demo video, install instructions.
- Outreach: Hacker News, Lobste.rs, r/programming, r/netsec, r/MachineLearning, OSS Security mailing list.
- Talk submissions: USENIX Security, DEF CON AI Village, BSides regional events, FOSDEM.

**Total estimate:** 56 weeks (~13 months) of focused part-time work. With life intervening, plan for 15–18 months.

---

## 18. Testing strategy

### 18.1 Unit tests

Per-crate. Standard `cargo test`. Targets:
- Manifest parser: edge cases, malformed TOML, unicode in paths.
- Validator: every semantic rule, every risk-score path.
- Policy compiler: template resolution, CEL compilation.
- IPC: round-trip serialization.
- Egress proxy: SNI extraction with malformed ClientHello.
- DNS resolver: wildcard matching, NXDOMAIN cases.

Coverage target: 80% line coverage in core crates. `cargo-llvm-cov` in CI.

### 18.2 Integration tests

In `tests/` workspace directory. Each test spins up a real daemon and exercises a full flow.

Test categories:
- **Sandbox correctness:** Spawn a real server, verify it runs, verify it has restricted access.
- **Negative tests:** Spawn a server that tries forbidden things; verify each is blocked AND logged.
- **Policy mediation:** Trigger tool-policy rules; verify decisions; verify audit events.
- **Approval flow:** Trigger approval; auto-respond; verify decision flows through.
- **Host integration:** Mock host config files; run `config sync`; verify rewrite; run `config unsync`; verify restoration is byte-identical to original.
- **Registry:** Mock registry HTTP server; fetch manifest; verify signature; install.
- **Crash recovery:** Kill daemon mid-operation; restart; verify state consistency.

### 18.3 Security tests

Specific malicious-behavior tests in `tests/security/`:

- **Exfiltration via HTTP POST:** server tries to POST `/etc/passwd` to attacker; verify blocked.
- **Exfiltration via DNS:** server tries to encode bytes in DNS subdomain queries to non-allowlisted host; verify blocked.
- **Filesystem traversal:** server tries to read `../../etc/shadow`; verify blocked.
- **Subprocess escape:** server tries to `execve("/bin/sh")`; verify blocked unless allowed.
- **Resource exhaustion:** server fork-bombs; verify cgroup pids.max enforces.
- **Memory bomb:** server allocates huge buffer; verify memory.max enforces.
- **Argument injection:** trigger a tool call with malicious args matching deny rules; verify denied.
- **Response leak:** server returns a known AWS key pattern; verify redacted.

All security tests double as documentation: each maps to a numbered item in the threat model.

### 18.4 Fuzzing

In `fuzz/` directory with `cargo-fuzz`.

Targets:
- `fuzz_manifest_parse` — random TOML bytes through the manifest parser.
- `fuzz_jsonrpc_parse` — random bytes through the shim's JSON-RPC parser.
- `fuzz_cel_compile` — random strings through CEL compilation.
- `fuzz_sni_parse` — random bytes through the SNI extractor.
- `fuzz_audit_replay` — random audit log bytes through the parser.

Run nightly in CI for 1 hour per target. Corpus persisted in `fuzz/corpus/`.

### 18.5 CI matrix

| Job | OS | Frequency |
|---|---|---|
| `cargo fmt --check` | Linux | every push |
| `cargo clippy -- -D warnings` | Linux, macOS | every push |
| `cargo build --release` | Linux (x86_64, aarch64), macOS (x86_64, aarch64) | every push |
| `cargo nextest run` | Linux, macOS | every push |
| `cargo-deny check` | Linux | every push |
| `cargo audit` | Linux | every push |
| Integration tests | Linux (Ubuntu 22.04, 24.04, Debian 12, Fedora), macOS 13/14/15 | every push to main |
| Security tests | Linux + macOS | every push to main |
| Fuzz (1h per target) | Linux | nightly |
| Coverage report | Linux | weekly |

---

## 19. Release and signing

### 19.1 Release artifacts

Per release, build:

**Linux:**
- `hatch-<version>-x86_64-unknown-linux-gnu.tar.gz`
- `hatch-<version>-aarch64-unknown-linux-gnu.tar.gz`
- Each tarball contains: `hatch`, `hatch-daemon`, `hatch-shim`, `LICENSE`, `README`, `install.sh`.
- SHA256SUMS file.
- `.sig` files (minisign).

**macOS:**
- `hatch-<version>.pkg` (universal binary, signed + notarized + stapled).
- SHA256SUMS.

### 19.2 Build pipeline

Triggered by tag push (`v*.*.*`).

```yaml
# .github/workflows/release.yml (sketch)
on:
  push:
    tags: ['v*.*.*']

jobs:
  build-linux:
    strategy:
      matrix:
        target: [x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu]
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - run: cargo build --release --target ${{ matrix.target }}
      - run: ./scripts/package-linux.sh ${{ matrix.target }}
      - uses: actions/upload-artifact@v4

  build-macos:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/build-macos-universal.sh
      - run: ./scripts/sign-macos.sh
        env:
          APPLE_DEVELOPER_ID: ${{ secrets.APPLE_DEVELOPER_ID }}
          APPLE_TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
          APPLE_APP_PASSWORD: ${{ secrets.APPLE_APP_PASSWORD }}
      - run: ./scripts/notarize-macos.sh
      - uses: actions/upload-artifact@v4

  sign-and-release:
    needs: [build-linux, build-macos]
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/download-artifact@v4
      - run: ./scripts/sign-releases.sh
        env:
          MINISIGN_PRIVATE_KEY: ${{ secrets.MINISIGN_PRIVATE_KEY }}
          MINISIGN_PASSWORD: ${{ secrets.MINISIGN_PASSWORD }}
      - uses: softprops/action-gh-release@v2
```

### 19.3 Package manager distribution

**Homebrew:** Maintain `malwarebo/homebrew-tap` repo. Formula auto-updated by release CI:

```ruby
class Hatch < Formula
  desc "Capability-based isolation for AI tool servers"
  homepage "https://hatch.sh"
  version "1.0.0"

  on_macos do
    url "https://github.com/malwarebo/hatch/releases/download/v1.0.0/hatch-1.0.0.pkg"
    sha256 "..."
  end

  on_linux do
    on_intel do
      url "https://github.com/malwarebo/hatch/releases/download/v1.0.0/hatch-1.0.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "..."
    end
    on_arm do
      url "https://github.com/malwarebo/hatch/releases/download/v1.0.0/hatch-1.0.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "..."
    end
  end

  def install
    bin.install "hatch", "hatch-daemon", "hatch-shim"
  end

  service do
    run [opt_bin/"hatch-daemon", "--launchd"]
    keep_alive true
  end
end
```

**AUR:** `hatch-bin` package, PKGBUILD auto-updated.

**Nix:** Flake in `malwarebo/nix-flake` repo.

### 19.4 Signing keys

| Key | Purpose | Storage |
|---|---|---|
| Apple Developer ID | macOS code signing | Apple-managed, in CI keychain via secrets |
| Apple App-Specific Password | Notarization | GitHub secret |
| Master ed25519 (manifests) | Sign delegated keys | Yubikey, offline |
| Delegated ed25519 (manifests) | Sign manifest bundles | GitHub Actions secret (encrypted) |
| Minisign (releases) | Sign release artifacts | Hardware token or air-gapped machine |

Key rotation policy in `signing/policy.md`.

---

## 20. Operational concerns

### 20.1 Vulnerability disclosure

Set up before public release:

- `SECURITY.md` with disclosure email (`security@hatch.sh`) and PGP key fingerprint.
- GitHub Security Advisories enabled.
- Response SLA: acknowledge within 72h, fix critical within 30d, coordinate disclosure.
- Hall of fame at `docs.hatch.sh/security/hall-of-fame`.

### 20.2 Release cadence

- **Patch (1.0.x):** as needed for bugs and security fixes. No new features.
- **Minor (1.x):** every 4–6 weeks. New features, backward-compatible schema additions.
- **Major (2.x):** only for breaking changes. Avoid for at least 18 months after 1.0.

### 20.3 Manifest schema versioning

- Version field required in every manifest.
- Daemon supports the last 2 schema major versions for backward compatibility.
- Schema changes go through an RFC process in `malwarebo/manifests` discussions.

### 20.4 Community

- Matrix room `#hatch:matrix.org` for chat.
- GitHub Discussions for longer-form Q&A.
- Monthly community call once contributor base justifies (don't start prematurely).
- Code of Conduct: Contributor Covenant 2.1.

### 20.5 Funding

Set up Day 1:
- GitHub Sponsors (no harm in having it before adoption).
- Apple Developer fee: $99/year baseline.
- Domain: ~$15/year.

Future (when adoption justifies):
- Open Collective.
- Sponsorship tiers for companies whose MCP servers are in the registry.
- OSS grants: OTF, Sovereign Tech Fund, NLnet.

Avoid VC funding. Hatch is infrastructure, not a startup.

### 20.6 Contributor onboarding

Plan Day 1 for the second contributor:

- `CONTRIBUTING.md` with concrete first-issue suggestions.
- Issues labeled `good-first-issue` and `help-wanted` from week one.
- Architecture docs in `docs/architecture/` that explain **why** not just **what**.
- Personal commitment: respond to PRs within 7 days even if just "ack, will review by date X."

### 20.7 Burnout protection

Hard rules from Day 1:

- Maximum 10 hours/week on the project.
- One full week off per quarter, no exceptions.
- Project can slip without it being a failure.
- It is OK to say "this won't be in 1.0" out loud.
- Security tickets get priority; everything else can wait.

The internet rewards people who ship security infrastructure and then quietly punishes them when they can't keep up. Be ready for the asymmetry; plan for it.

---

## 21. Open questions and deferred decisions

These are not blockers for starting, but should be resolved before the relevant phase begins.

### 21.1 Resolve before Phase A

- [ ] Confirm GitHub org name available: `malwarebo` vs `hatchproject`.
- [ ] Confirm crates.io names available: `hatch`, `hatch-cli`, `hatch-daemon`, `hatch-shim`, plus library crates.
- [ ] Confirm domain availability: `hatch.sh`, fallback `hatch.dev`.
- [ ] Pick logo direction (commission or self-design).
- [ ] Pick accent color.
- [ ] Choose between mdBook and Astro Starlight for docs (mdBook recommended).

### 21.2 Resolve before Phase B

- [ ] Decide: direct syscall sandbox setup vs invoking `bwrap` as subprocess. Recommendation: direct syscalls for tighter control, but ship a `bwrap` fallback for the first internal milestone.
- [ ] Pick seccomp profile starting point (Docker default vs systemd-nspawn default).
- [ ] Decide initial iptables-or-nftables choice for netns rules (nftables on modern distros, iptables-legacy fallback).

### 21.3 Resolve before Phase C

- [ ] Apple Developer account enrollment (start at week 1 if possible; can take days to approve).
- [ ] Decide on `pkgbuild` vs `dmg` distribution (pkg recommended for daemon install).
- [ ] Endpoint Security entitlement application — start as early as possible, may take months.

### 21.4 Resolve before Phase E

- [ ] Choose CEL crate: `cel-interpreter` (Rust-native) vs FFI to Google's C++ impl. Recommendation: Rust-native.
- [ ] Decide on default approval timeout (60s suggested).
- [ ] Approval UI on Linux: D-Bus only, or also bundle a small `notify-rust` fallback.

### 21.5 Long-term questions (not 1.0 blockers)

- Should hatch support remote MCP servers in 2.x? (Different trust model; probably not.)
- Should hatch grow a daemon-side capability broker for non-MCP AI tools? (Tempting; out of scope for 1.0.)
- Should there be a managed enterprise SaaS variant for centralized policy management? (Wait until adoption justifies it.)
- Windows support: under what conditions would this become a priority? (Probably never solo; potentially as a contributor-led port.)

---

## 22. Week-one checklist

Concrete, ordered. Do these in this order:

### Day 1
1. Register GitHub org. Reserve both candidate names.
2. Register domain. Reserve both candidates.
3. Reserve crates.io names (publish empty placeholder crates).
4. Create `malwarebo/hatch` repo. Add `README.md`, `LICENSE` (Apache 2.0), `NOTICE`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `SECURITY.md` (with placeholder PGP key), `CONTRIBUTING.md`.

### Day 2
5. Create the Cargo workspace with all crates listed in §4.1. Each crate has minimal `lib.rs` or `main.rs` so `cargo check` passes.
6. Set up CI: `.github/workflows/ci.yml` with fmt, clippy, build, test on Linux + macOS runners. Make it green.
7. Add `deny.toml` and the security-audit workflow.

### Day 3
8. Set up the docs site scaffold. `docs/book.toml` + `docs/src/` with stubs for the structure in §16.1. Get it building locally.
9. Configure GitHub Pages or Cloudflare Pages to publish docs from `main`.

### Day 4
10. **Write the threat model page in `docs/src/concepts/threat-model.md`.** Don't write any code until this is done. Use §2 of this document as the source.
11. Write the manifest schema page in `docs/src/reference/manifest-schema.md`. Use §6 as the source.

### Day 5
12. Start Phase A coding. First task: `hatch-ipc` crate. Define the message types from §13. Round-trip serialization tests pass.
13. Second task: `hatch-audit` crate. Implement the JSONL writer with rotation.

### Day 6–7
14. `hatch-state` crate: SQLite schema, migrations, basic CRUD for `manifests` table.
15. `hatch-daemon` skeleton: starts up, opens unix socket, accepts connections, responds to a `DaemonStatus` request.
16. `hatch-cli` skeleton: `hatch daemon status` works against the running daemon.
17. Tag the end of the week as `v0.0.0-week1` in your private notes. Take a break.

By end of week 1, you have a published Cargo workspace, CI green, docs site live with the threat model, daemon skeleton, and CLI that can talk to the daemon. No sandboxing yet, but the foundation is real.

---

## Appendix A — Cargo workspace template

`Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
    "crates/hatch-cli",
    "crates/hatch-daemon",
    "crates/hatch-shim",
    "crates/hatch-core",
    "crates/hatch-sandbox",
    "crates/hatch-sandbox-linux",
    "crates/hatch-sandbox-macos",
    "crates/hatch-proxy",
    "crates/hatch-protocol",
    "crates/hatch-audit",
    "crates/hatch-state",
    "crates/hatch-registry",
    "crates/hatch-hostcfg",
    "crates/hatch-ipc",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
repository = "https://github.com/malwarebo/hatch"
authors = ["The hatch authors"]

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
rustix = { version = "0.38", features = ["fs", "process", "net"] }
rusqlite = { version = "0.31", features = ["bundled"] }
sha2 = "0.10"
blake3 = "1"
ed25519-dalek = "2"
rustls = "0.23"
tokio-rustls = "0.26"
hickory-resolver = "0.24"
hickory-server = "0.24"
ratatui = "0.26"
crossterm = "0.27"
prometheus = "0.13"
thiserror = "1"
anyhow = "1"
simd-json = "0.13"
cel-interpreter = "0.7"
uuid = { version = "1", features = ["v4", "serde"] }
time = { version = "0.3", features = ["serde", "formatting"] }
glob = "0.3"
regex = "1"

[profile.release]
lto = "thin"
codegen-units = 1
strip = true
```

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.83.0"
components = ["rustfmt", "clippy", "rust-src"]
profile = "minimal"
```

`deny.toml`:

```toml
[bans]
multiple-versions = "warn"
deny = [
    { name = "openssl" },
    { name = "openssl-sys" },
    { name = "nix" },
]

[licenses]
allow = [
    "Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC",
    "CC0-1.0", "Unicode-DFS-2016", "Unlicense", "Zlib",
]
confidence-threshold = 0.9

[advisories]
yanked = "deny"
unmaintained = "warn"
unsound = "deny"
```

---

## Appendix B — Reference: minimal manifest

Smallest valid manifest, for testing:

```toml
schema_version = "1.0"
name = "example"
version = "0.1.0"
description = "Minimal manifest for testing"

[command]
program = "/usr/bin/cat"
args = []

[network]
allow_https = []
allow_dns = []

[filesystem]
read = []
write = []
tmpfs = ["/tmp"]

[env]
passthrough = []

[exec]
allow_subprocess = false
allow_binaries = []

[resources]
memory_mb = 64
cpu_percent = 10
pids_max = 10
nofile = 32
tool_call_timeout_seconds = 30

[tool_policy]
require_approval = []
deny = []

[platform.linux]
seccomp_preset = "strict"
landlock = true

[platform.macos]
endpoint_security = false
```

---

## Appendix C — Glossary

| Term | Definition |
|---|---|
| **MCP** | Model Context Protocol. Anthropic-originated protocol for AI tool servers. |
| **MCP server** | A process exposing tools to an LLM over MCP (typically stdio JSON-RPC). |
| **MCP host** | An application that spawns MCP servers (Claude Desktop, Cursor, etc.). |
| **Manifest** | A signed TOML document declaring a server's capability requirements. |
| **Sandbox backend** | Per-OS implementation of isolation (Linux: bwrap/namespaces; macOS: sandbox-exec). |
| **SNI** | Server Name Indication. TLS extension carrying the destination hostname. |
| **CEL** | Common Expression Language. Google's sandboxed expression language. |
| **Landlock** | Linux LSM for path-based access control without privilege. |
| **Endpoint Security** | macOS framework for kernel-level security monitoring. Requires Apple entitlement. |
| **PF** | Packet Filter. macOS's kernel firewall. |
| **Shim** | The `hatch-shim` binary that MCP hosts spawn instead of the real server. |
| **Approval flow** | The user-prompt mechanism for tool calls requiring confirmation. |
| **Risk score** | A heuristic permission-breadth score computed from a manifest. |

---

**End of plan.**

This document is the contract. When in doubt during implementation, refer back to it. When the implementation diverges from the plan, update the plan in the same PR — the docs and code stay in sync or the project loses coherence.
