# macOS demo

Shows hatch enforcing a manifest's network allowlist on the real macOS
sandbox. Run from the repository root.

## One command

```bash
./scripts/demo-macos.sh
```

Runs three scenarios: a token-theft attempt blocked, an allowlisted host that
still works through the proxy, and the same request denied when the host is not
on the allowlist.

## Manual walkthrough

Build once:

```bash
cargo build -p hatch-daemon -p hatch-cli -p hatch-shim
mkdir -p .hatch-run
```

Start the daemon (leave running):

```bash
./target/debug/hatch-daemon --foreground --real-sandbox --enable-proxy \
  --state-dir ./.hatch-run --socket ./.hatch-run/d.sock
```

In another terminal:

```bash
H="./target/debug/hatch --socket ./.hatch-run/d.sock --state-dir ./.hatch-run"

# allowlisted host -> HTTP 200 (reaches example.com through the proxy)
$H install --file examples/demo/allowed.toml --allow-unsigned
$H run allowed --seconds 12

# empty allowlist -> blocked at the proxy
$H install --file examples/demo/blocked.toml --allow-unsigned
$H run blocked --seconds 12

$H audit --limit 10
```

Run one server at a time. Stop with `$H daemon stop` and `rm -rf ./.hatch-run`.

## Before / after

Run `blocked` without `--real-sandbox` (passthrough stub) first to show the
request succeeding unprotected, then again with `--real-sandbox --enable-proxy`
to show it denied.
