# hatch manifest registry

This directory is the source for `malwarebo/manifests`, the signed registry
that `hatch registry update` pulls from.

Each subdirectory under `servers/` is one manifest. A manifest must:

- Declare an exact, narrow set of network destinations.
- Declare every filesystem path the server needs (or none).
- Justify any `allow_subprocess = true`.
- Pass `hatch manifest validate` cleanly.
- Include a `README.md` explaining what the server does and why each
  permission is needed.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and the schema in
[`schema/manifest.schema.json`](schema/manifest.schema.json).
