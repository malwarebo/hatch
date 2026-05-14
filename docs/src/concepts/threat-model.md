# Threat model

This page is the contract between hatch and its users. Every claim here must
be defensible. If hatch grows a guarantee, this page changes first. If hatch
stops being able to defend a guarantee, this page changes first.

## Assets being protected

- User credentials on disk: SSH keys, cloud credentials, API tokens, password
  manager databases.
- Source code and project files outside the scope a server should see.
- Network identity: the ability to make authenticated requests from the
  user's machine to arbitrary destinations.
- Local resources: CPU, memory, file descriptors, processes.

## Adversaries

- **Malicious server author.** Publishes a fake or typosquatted MCP server.
- **Supply-chain attacker.** Compromises a legitimate server's dependency.
- **Indirect prompt-injection actor.** Plants instructions in content the LLM
  reads (webpages, PDFs, issues, emails) that cause the agent to invoke tools
  with malicious arguments.
- **Buggy legitimate server.** Misbehaves in ways the author did not intend.

## Trust assumptions

Trusted (in the user's TCB):

- The host operating system kernel.
- The MCP host application (Claude Desktop, Cursor, Claude Code, etc.).
- The hatch daemon, CLI, and shim binaries after signature verification at
  install time.
- The hatch manifest signing keys.
- The user's package manager and the integrity of installed packages it
  verifies.

Untrusted:

- Any MCP server binary, script, or library.
- All dependencies of MCP servers.
- Any content the LLM processes.
- Any input arriving over the network.

## What hatch protects against

1. Malicious server reading files outside its declared filesystem scope
   (`~/.ssh`, `~/.aws`, sibling projects).
2. Malicious server exfiltrating data to attacker-controlled hosts.
3. Malicious server exhausting resources.
4. Server tricked by prompt injection into invoking a destructive tool.
   Mitigated by protocol mediation and approval flows.
5. Server tricked into invoking a legitimate tool with malicious arguments.
   Mitigated by CEL-based argument rules.
6. Server leaking secrets in tool responses to the LLM. Mitigated by
   response filters.
7. Compromised server spawning subprocesses to bypass its constraints.
   Mitigated by subprocess policy plus seccomp `execve` filtering on Linux.

## What hatch does NOT protect against

Honesty about limits is what makes the protections credible.

1. **The MCP host itself being compromised.** If Claude Desktop is malicious,
   hatch is bypassed.
2. **The LLM choosing to misuse an allowed tool.** If the manifest allows
   `filesystem.write` to `$PROJECT_ROOT`, the LLM can be tricked into
   corrupting `$PROJECT_ROOT/.env`.
3. **DNS-tunneled exfiltration to allowlisted domains.** A compromised server
   can encode data in subdomain queries to an allowlisted host.
4. **Side-channel attacks** (timing, cache, power).
5. **Kernel exploits.** Mitigated by keeping the OS patched.
6. **Network attacks on allowlisted destinations.** If `api.github.com` is
   compromised, hatch does not help.
7. **User-supplied permissive manifests.** A manifest that grants
   `read=["/"]` defeats the purpose. The risk-score system warns but does
   not prevent.
8. **Account compromise on allowlisted services.** Your GitHub token used
   legitimately by a sandboxed server is still your GitHub token.
9. **Windows.** Not supported.
10. **Remote MCP servers.** hatch sandboxes the local stdio transport.
    Remote servers are out of scope.

## Per-platform guarantee table

| Capability | Linux | macOS (default) | macOS (entitled) |
|---|---|---|---|
| Filesystem access restricted to manifest paths | Kernel-enforced (mount namespace + Landlock) | Kernel-enforced (TrustedBSD via `sandbox-exec`) | Kernel-enforced + Endpoint Security monitoring |
| Network egress restricted to allowlist | Kernel-enforced (netns, no other route) | Kernel-enforced (PF rules by UID) | Same plus ES connect events |
| DNS restricted to allowlist | Kernel-enforced (no other resolver reachable) | Cooperation-enforced (PF blocks alt resolvers) | Same |
| Syscall surface restricted | Yes (seccomp-bpf) | No platform primitive | Partial (ES auth events) |
| Resource limits enforced | Yes (cgroups v2) | Yes (`setrlimit`) | Yes |
| Subprocess spawning restricted | Yes (seccomp `execve` filter) | Yes (`sandbox-exec` `process-exec`) | Yes |
| No privilege escalation possible | Yes (caps dropped, `no_new_privs`) | Yes (non-root UID, no `setuid` binaries reachable) | Yes |
