# Contributing a manifest

1. Pick a server you want to use under hatch.
2. Run `hatch observe -- <server-command> ...` against a real workload.
3. Hand-edit the resulting candidate into `servers/<name>/manifest.toml`.
4. Tighten everything:
   - Network: narrowest hostname allowlist possible. No `"*"` unless the
     server is genuinely an HTTP fetcher.
   - Filesystem: narrowest paths. Use `$PROJECT_ROOT`, `$HATCH_STATE_DIR`,
     `$HATCH_RUNTIME_DIR` instead of `$HOME`.
   - `allow_subprocess`: only if the server genuinely shells out, with each
     binary in `allow_binaries`.
5. Write `servers/<name>/README.md` covering: what the server does, why these
   permissions, known issues.
6. Write `servers/<name>/test/smoke.sh` that exercises the main tool.
7. Validate locally: `hatch manifest validate servers/<name>/manifest.toml`.
8. Open a PR.

Reviewers focus on:

- Are network destinations minimal?
- Are filesystem write paths necessary and bounded?
- Is `allow_subprocess` justified?
- Does the risk score match the actual capability needs?
