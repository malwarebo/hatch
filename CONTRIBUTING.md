# Contributing to hatch

Thank you for your interest in contributing. Before you start:

1. Read the [threat model](docs/src/concepts/threat-model.md). Most design
   debates trace back to it.
2. Look for issues labelled `good-first-issue` or `help-wanted`.

## Development setup

Requirements:

- Rust stable (1.83 or newer). `rust-toolchain.toml` pins the channel.
- On Linux: a kernel with user namespaces, cgroups v2, seccomp, Landlock
  (5.13+). Most modern distros qualify.
- On macOS: 13 Ventura or newer.

```bash
# Build everything
cargo build --workspace

# Lints (CI runs `-D warnings`)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Tests
cargo test --workspace

# License / advisory checks
cargo install cargo-deny
cargo deny check
```

## Pull request expectations

- One logical change per PR.
- Tests for new behaviour. Security-relevant code must include a negative
  test that demonstrates the protection actually works.
- `cargo fmt`, `cargo clippy`, and `cargo test` must pass.
- For security-sensitive changes, include a short note about how it relates
  to the threat model.

## Architectural changes

If you want to change anything in the layered architecture, open
a discussion first. Lower layers know nothing about higher layers; please
preserve that invariant.

## Reporting security issues

See [`SECURITY.md`](SECURITY.md). Do not file public issues.
