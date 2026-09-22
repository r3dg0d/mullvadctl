use crate::mullvad::client;
use crate::mullvad::parse::parse_status;
use crate::net::check::{fetch_public_ip, read_dns_resolvers, list_ipv6_addrs};
use crate::util::config::AppConfig;
use crate::util::output::OutputOpts;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
pub struct StatusReport {
    pub mullvad: crate::mullvad::parse::MullvadStatus,
    pub exit_ip: crate::net::check::PublicIpInfo,
    pub dns: crate::net::check::DnsInfo,
    pub ipv6: Vec<String>,
    pub kill_switch_hint: String,
    pub lockdown_hint: String,
}

pub fn run(out: &OutputOpts, cfg: &AppConfig) -> Result<()> {
    let raw = client::run_mullvad_ok(&["status"])?;
    let mullvad = parse_status(&raw);
    out.print_verbose(&format!("raw status:\n{raw}"));

    let exit_ip = fetch_public_ip(cfg.ip_check_url.as_deref());
    let dns = read_dns_resolvers();
    let ipv6 = list_ipv6_addrs();

    // kill-switch / lockdown: try settings get if available
    let (ks, ld) = settings_hints();

    let report = StatusReport {
        mullvad: mullvad.clone(),
        exit_ip: exit_ip.clone(),
        dns: dns.clone(),
        ipv6: ipv6.clone(),
        kill_switch_hint: ks,
        lockdown_hint: ld,
    };

    out.emit_or_human(&report, || {
        let mut s = String::new();
        s.push_str(&format!("State: {}\n", report.mullvad.state));
        if let Some(r) = &report.mullvad.relay {
            s.push_str(&format!("Relay: {r}\n"));
        }
        if let Some(l) = &report.mullvad.location {
            s.push_str(&format!("Location: {l}\n"));
        }
        if let Some(ip) = &report.exit_ip.ip {
            s.push_str(&format!("Exit IP: {ip}\n"));
        }
        if let Some(c) = &report.exit_ip.country {
            s.push_str(&format!("Country: {c}\n"));
        }
        if let Some(city) = &report.exit_ip.city {
            s.push_str(&format!("City: {city}\n"));
        }
        if let Some(org) = &report.exit_ip.organization {
            s.push_str(&format!("ASN/Org: {org}\n"));
        }
        if let Some(m) = report.exit_ip.mullvad_exit_ip {
            s.push_str(&format!("Mullvad exit IP: {m}\n"));
        }
        if let Some(t) = &report.mullvad.tunnel_type {
            s.push_str(&format!("Tunnel: {t}\n"));
        }
        s.push_str(&format!("DNS: {}\n", report.dns.resolvers.join(", ")));
        if report.ipv6.is_empty() {
            s.push_str("IPv6 global: (none)\n");
        } else {
            s.push_str(&format!("IPv6 global: {}\n", report.ipv6.join(", ")));
        }
        s.push_str(&format!("Kill-switch: {}\n", report.kill_switch_hint));
        s.push_str(&format!("Lockdown: {}\n", report.lockdown_hint));
        s.push_str("\nNote: mullvadctl is a companion helper — Mullvad owns tunnel security.\n");
        s
    })?;
    Ok(())
}

fn settings_hints() -> (String, String) {
    let ks = match client::run_mullvad_ok(&["lan", "get"]) {
        Ok(s) => format!("see `mullvad` settings; lan get => {}", s.trim()),
        Err(_) => "query via `mullvad lockdown-mode get` / app settings".into(),
    };
    let ld = match client::run_mullvad_ok(&["lockdown-mode", "get"]) {
        Ok(s) => s.trim().to_string(),
        Err(_) => "unavailable (try `mullvad lockdown-mode get`)".into(),
    };
    // Also try kill-switch style
    let _ = ks;
    let ks = match client::run_mullvad_ok(&["tunnel", "get"]) {
        Ok(s) => s.trim().chars().take(120).collect::<String>(),
        Err(_) => "use official `mullvad` CLI / GUI for kill-switch status".into(),
    };
    (ks, ld)
}
