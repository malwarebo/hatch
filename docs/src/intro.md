# hatch

Capability-based isolation for AI tool servers.

hatch sandboxes MCP (Model Context Protocol) servers on Linux and macOS,
enforcing per-server network, filesystem, and protocol-level policies declared
in signed manifests.

Start with the [threat model](./concepts/threat-model.md). Everything hatch
protects against, and everything it does not, is documented there.
