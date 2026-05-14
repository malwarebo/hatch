use std::process::Command;

use anyhow::{anyhow, Result};

pub struct NetnsHandle {
    pub name: String,
    pub host_veth: String,
    pub sandbox_veth: String,
    pub host_ip: String,
    pub sandbox_ip: String,
    pub proxy_port: u16,
    pub dns_port: u16,
}

pub fn create_for(server_id: &str, proxy_port: u16, dns_port: u16) -> Result<NetnsHandle> {
    let short = &server_id.chars().take(8).collect::<String>();
    let name = format!("hatch-{short}");
    let host_veth = format!("hatch-{short}-h");
    let sandbox_veth = format!("hatch-{short}-s");
    let host_ip = format!("10.99.{}.1", short_to_octet(short));
    let sandbox_ip = format!("10.99.{}.2", short_to_octet(short));

    run("ip", &["netns", "add", &name])?;
    run(
        "ip",
        &[
            "link",
            "add",
            &host_veth,
            "type",
            "veth",
            "peer",
            "name",
            &sandbox_veth,
        ],
    )?;
    run("ip", &["link", "set", &sandbox_veth, "netns", &name])?;
    run(
        "ip",
        &["addr", "add", &format!("{host_ip}/30"), "dev", &host_veth],
    )?;
    run("ip", &["link", "set", &host_veth, "up"])?;
    run(
        "ip",
        &[
            "netns",
            "exec",
            &name,
            "ip",
            "addr",
            "add",
            &format!("{sandbox_ip}/30"),
            "dev",
            &sandbox_veth,
        ],
    )?;
    run(
        "ip",
        &[
            "netns",
            "exec",
            &name,
            "ip",
            "link",
            "set",
            &sandbox_veth,
            "up",
        ],
    )?;
    run(
        "ip",
        &["netns", "exec", &name, "ip", "link", "set", "lo", "up"],
    )?;
    run(
        "ip",
        &[
            "netns", "exec", &name, "ip", "route", "add", "default", "via", &host_ip,
        ],
    )?;

    let proxy_port_str = proxy_port.to_string();
    let dns_port_str = dns_port.to_string();
    let dnat_443 = format!("DNAT --to-destination {host_ip}:{proxy_port_str}");
    let dnat_53 = format!("DNAT --to-destination {host_ip}:{dns_port_str}");
    let _ = dnat_443;
    let _ = dnat_53;
    let _ = run(
        "ip",
        &[
            "netns",
            "exec",
            &name,
            "iptables",
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "443",
            "-j",
            "DNAT",
            "--to-destination",
            &format!("{host_ip}:{proxy_port_str}"),
        ],
    );
    let _ = run(
        "ip",
        &[
            "netns",
            "exec",
            &name,
            "iptables",
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "DNAT",
            "--to-destination",
            &format!("{host_ip}:{dns_port_str}"),
        ],
    );
    let _ = run(
        "ip",
        &[
            "netns", "exec", &name, "iptables", "-A", "OUTPUT", "-d", &host_ip, "-j", "ACCEPT",
        ],
    );
    let _ = run(
        "ip",
        &[
            "netns", "exec", &name, "iptables", "-A", "OUTPUT", "-j", "DROP",
        ],
    );
    let _ = run(
        "ip",
        &[
            "netns", "exec", &name, "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT",
        ],
    );
    let _ = run(
        "ip",
        &[
            "netns", "exec", &name, "iptables", "-A", "INPUT", "-j", "DROP",
        ],
    );

    Ok(NetnsHandle {
        name,
        host_veth,
        sandbox_veth,
        host_ip,
        sandbox_ip,
        proxy_port,
        dns_port,
    })
}

pub fn destroy(handle: &NetnsHandle) {
    let _ = run("ip", &["netns", "del", &handle.name]);
    let _ = run("ip", &["link", "del", &handle.host_veth]);
}

fn short_to_octet(s: &str) -> u8 {
    let mut acc: u32 = 0;
    for b in s.bytes() {
        acc = acc.wrapping_mul(31).wrapping_add(b as u32);
    }
    (acc % 250 + 2) as u8
}

fn run(prog: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(prog)
        .args(args)
        .status()
        .map_err(|e| anyhow!("exec {prog}: {e}"))?;
    if !status.success() {
        return Err(anyhow!(
            "{prog} {} exited with {:?}",
            args.join(" "),
            status.code()
        ));
    }
    Ok(())
}
