use hatch_core::CompiledPolicy;
use std::fmt::Write;

pub fn render_sandbox_exec_profile(
    policy: &CompiledPolicy,
    runtime_dir: &str,
    proxy_port: u16,
    dns_port: u16,
) -> String {
    let mut sb = String::new();
    sb.push_str("(version 1)\n");
    sb.push_str("(deny default)\n\n");

    sb.push_str("(allow process-fork)\n");
    sb.push_str("(allow process-info-pidinfo (target self))\n");
    sb.push_str("(allow signal (target self))\n\n");

    sb.push_str("(allow file-read-data file-write-data\n");
    sb.push_str("       (literal \"/dev/stdin\")\n");
    sb.push_str("       (literal \"/dev/stdout\")\n");
    sb.push_str("       (literal \"/dev/stderr\")\n");
    sb.push_str("       (literal \"/dev/null\")\n");
    sb.push_str("       (literal \"/dev/urandom\")\n");
    sb.push_str("       (literal \"/dev/random\"))\n\n");

    sb.push_str("(allow file-read* file-read-metadata\n");
    sb.push_str("       (subpath \"/usr/lib\")\n");
    sb.push_str("       (subpath \"/usr/share\")\n");
    sb.push_str("       (subpath \"/System/Library\")\n");
    sb.push_str("       (subpath \"/Library/Frameworks\")\n");
    sb.push_str("       (subpath \"/private/etc/ssl\"))\n\n");

    sb.push_str("(allow sysctl-read)\n\n");

    sb.push_str("(allow mach-lookup\n");
    sb.push_str("       (global-name \"com.apple.system.notification_center\")\n");
    sb.push_str("       (global-name \"com.apple.system.logger\"))\n\n");

    for path in &policy.resolved_paths_read {
        let _ = writeln!(
            sb,
            "(allow file-read* file-read-metadata (subpath \"{}\"))",
            sb_quote(&path.to_string_lossy())
        );
    }
    for path in &policy.resolved_paths_write {
        let _ = writeln!(
            sb,
            "(allow file-read* file-write* (subpath \"{}\"))",
            sb_quote(&path.to_string_lossy())
        );
    }
    let _ = writeln!(
        sb,
        "(allow file-read* file-write* (subpath \"{}\"))",
        sb_quote(runtime_dir)
    );
    sb.push('\n');

    let _ = writeln!(
        sb,
        "(allow network-outbound (remote tcp \"127.0.0.1:{proxy_port}\"))"
    );
    let _ = writeln!(
        sb,
        "(allow network-outbound (remote udp \"127.0.0.1:{dns_port}\"))"
    );
    sb.push('\n');

    if policy.manifest.exec.allow_subprocess {
        if policy.manifest.exec.allow_binaries.is_empty() {
            sb.push_str("(allow process-exec)\n");
        } else {
            for bin in &policy.manifest.exec.allow_binaries {
                let _ = writeln!(sb, "(allow process-exec (literal \"{}\"))", sb_quote(bin));
            }
        }
    }

    let extra = policy.manifest.platform.macos.extra_sbpl.trim();
    if !extra.is_empty() {
        sb.push('\n');
        sb.push_str(extra);
        if !extra.ends_with('\n') {
            sb.push('\n');
        }
    }
    sb
}

pub fn render_launchd_plist(install_dir: &str, log_dir: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>sh.hatch.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>{install_dir}/hatch-daemon</string>
        <string>--launchd</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/>
        <key>Crashed</key><true/>
    </dict>
    <key>ThrottleInterval</key><integer>10</integer>
    <key>StandardOutPath</key><string>{log_dir}/daemon.out.log</string>
    <key>StandardErrorPath</key><string>{log_dir}/daemon.err.log</string>
    <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
"#
    )
}

pub fn render_uid_installer() -> String {
    let mut s = String::new();
    s.push_str("#!/usr/bin/env bash\n");
    s.push_str("set -euo pipefail\n\n");
    s.push_str("for i in $(seq -f \"%03g\" 1 64); do\n");
    s.push_str("    user=\"_hatch_${i}\"\n");
    s.push_str("    uid=$((300 + 10#${i}))\n");
    s.push_str("    if dscl . -read /Users/${user} >/dev/null 2>&1; then continue; fi\n");
    s.push_str("    sudo dscl . -create /Users/${user}\n");
    s.push_str("    sudo dscl . -create /Users/${user} UserShell /usr/bin/false\n");
    s.push_str("    sudo dscl . -create /Users/${user} NFSHomeDirectory /var/empty\n");
    s.push_str("    sudo dscl . -create /Users/${user} UniqueID ${uid}\n");
    s.push_str("    sudo dscl . -create /Users/${user} PrimaryGroupID 300\n");
    s.push_str("    sudo dscl . -create /Users/${user} RealName \"Hatch Sandbox ${i}\"\n");
    s.push_str("    sudo dscl . -create /Users/${user} Password \"*\"\n");
    s.push_str(
        "    sudo dscl . -append /Groups/_hatch GroupMembership ${user} 2>/dev/null || true\n",
    );
    s.push_str("done\n");
    s
}

fn sb_quote(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hatch_core::{compile::compile, manifest::Manifest, template::TemplateContext};

    const MIN: &str = include_str!("../../hatch-core/tests/fixtures/minimal.toml");

    #[test]
    fn profile_renders() {
        let m = Manifest::parse_str(MIN).unwrap();
        let policy = compile(&m, &TemplateContext::empty()).unwrap();
        let sb = render_sandbox_exec_profile(&policy, "/tmp/x", 8443, 1053);
        assert!(sb.starts_with("(version 1)"));
        assert!(sb.contains("(deny default)"));
        assert!(sb.contains("127.0.0.1:8443"));
        assert!(sb.contains("127.0.0.1:1053"));
        assert!(sb.contains("subpath \"/tmp/x\""));
    }

    #[test]
    fn profile_includes_extra_sbpl() {
        let mut m = Manifest::parse_str(MIN).unwrap();
        m.platform.macos.extra_sbpl = "(allow distributed-notification-post)".into();
        let policy = compile(&m, &TemplateContext::empty()).unwrap();
        let sb = render_sandbox_exec_profile(&policy, "/tmp/x", 8443, 1053);
        assert!(sb.contains("(allow distributed-notification-post)"));
    }

    #[test]
    fn launchd_plist_well_formed() {
        let p = render_launchd_plist("/usr/local/bin", "/var/log/hatch");
        assert!(p.contains("sh.hatch.daemon"));
        assert!(p.contains("/usr/local/bin/hatch-daemon"));
        assert!(p.contains("/var/log/hatch/daemon.out.log"));
    }

    #[test]
    fn uid_installer_script_has_dscl() {
        let s = render_uid_installer();
        assert!(s.contains("dscl . -create"));
        assert!(s.starts_with("#!/usr/bin/env bash"));
    }
}
