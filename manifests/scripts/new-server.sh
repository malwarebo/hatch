#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 1 ]; then
    echo "usage: $0 <slug>" >&2
    exit 2
fi
name="$1"
dir="servers/$name"
if [ -d "$dir" ]; then
    echo "$dir already exists" >&2
    exit 1
fi
mkdir -p "$dir/test"

cat > "$dir/manifest.toml" <<EOF
schema_version = "1.0"
name = "$name"
version = "0.1.0"
description = "TODO"
license = "MIT"

[command]
program = "TODO"
args = []
working_dir = "\$HATCH_RUNTIME_DIR"

[network]
allow_https = []
allow_dns = []
allow_http = false

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
memory_mb = 256
cpu_percent = 25
pids_max = 25
nofile = 128
tool_call_timeout_seconds = 60

[tool_policy]
require_approval = []
deny = []

[platform.linux]
seccomp_preset = "strict"
landlock = true

[platform.macos]
endpoint_security = false
EOF

cat > "$dir/README.md" <<EOF
# $name

TODO: describe what this server does and why each permission is needed.
EOF

cat > "$dir/test/smoke.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# TODO: exercise the server's primary tool here.
EOF
chmod +x "$dir/test/smoke.sh"

echo "scaffolded $dir"
