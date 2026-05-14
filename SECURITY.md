# Security policy

hatch is a security tool. Vulnerabilities in hatch can defeat the protections
users rely on. We treat reports seriously.

## Reporting a vulnerability

**Do not file public GitHub issues for security bugs.**

Email `security@hatch.sh`. PGP key fingerprint will be published at
`https://hatch.sh/.well-known/pgp-key.asc` before the 1.0 release.

Alternatively, use [GitHub Security Advisories]
(https://github.com/malwarebo/hatch/security/advisories/new) to file a
private report.

## Response SLA

- Acknowledgement: within 72 hours.
- Triage and severity assignment: within 7 days.
- Fix for critical issues: within 30 days, coordinated with the reporter.
- Public disclosure: only after a fix is available and users have had a
  reasonable window to upgrade.

## Scope

In scope:

- The `hatch`, `hatch-daemon`, and `hatch-shim` binaries.
- Manifest schema, validation, signature verification.
- Sandbox backends (Linux and macOS).
- IPC protocol between CLI, daemon, and shim.
- Registry client and signature verification.
- Anything that materially weakens the guarantees in the
  [threat model](docs/src/concepts/threat-model.md).

Out of scope:

- Vulnerabilities in the MCP host application (Claude Desktop, Cursor, …).
- Vulnerabilities in a sandboxed MCP server itself, where hatch correctly
  enforces the manifest's declared policy.
- User-supplied permissive manifests (e.g. `read = ["/"]`).
- Anything explicitly listed under "What hatch does NOT protect against"
  in the threat model.

## Hall of fame

Researchers who report valid vulnerabilities get credited at
`docs.hatch.sh/security/hall-of-fame` (with permission).
