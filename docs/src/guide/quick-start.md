# Quick start

## Build

```bash
git clone https://github.com/malwarebo/hatch
cd hatch
cargo build --workspace
```

## Run the daemon

```bash
cargo run -p hatch-daemon -- --foreground --state-dir ./.hatch-state &
```

The daemon listens on `./.hatch-state/runtime/daemon.sock` and writes audit
logs under `./.hatch-state/audit/`.

## Use the CLI

```bash
cargo run -p hatch-cli -- --state-dir ./.hatch-state daemon status
cargo run -p hatch-cli -- manifest validate examples/manifests/minimal.toml
cargo run -p hatch-cli -- --state-dir ./.hatch-state \
    install --file examples/manifests/minimal.toml --allow-unsigned
cargo run -p hatch-cli -- --state-dir ./.hatch-state list
cargo run -p hatch-cli -- --state-dir ./.hatch-state run minimal --seconds 2
cargo run -p hatch-cli -- --state-dir ./.hatch-state audit
cargo run -p hatch-cli -- --state-dir ./.hatch-state daemon stop
```

By default `run` uses the passthrough stub backend. Pass `--real-sandbox` to
the daemon to enable the Linux or macOS backend, and `--enable-proxy` to
start the SNI proxy and DNS allowlist resolver.
