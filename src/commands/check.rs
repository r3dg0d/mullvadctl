use crate::mullvad::client;
use crate::mullvad::parse::parse_status;
use crate::net::check::{
    connectivity_report, dns_leak_heuristics, fetch_public_ip,
};
use crate::util::config::AppConfig;
use crate::util::output::OutputOpts;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
struct CheckReport {
    before_note: String,
    vpn_status: crate::mullvad::parse::MullvadStatus,
    connectivity: crate::net::check::ConnectivityReport,
    dns_heuristics: Vec<String>,
    verification: Vec<String>,
}

pub fn run(out: &OutputOpts, cfg: &AppConfig) -> Result<()> {
    // "before/after style": capture IP, then re-check after reading VPN state
    let ip_before = fetch_public_ip(cfg.ip_check_url.as_deref());
    let raw = client::run_mullvad_ok(&["status"])?;
    let vpn = parse_status(&raw);
    let connectivity = connectivity_report(cfg.ip_check_url.as_deref());
    let heuristics = dns_leak_heuristics(&connectivity.dns, vpn.connected);

    let mut verification = Vec::new();
    if vpn.connected {
        verification.push("Mullvad reports Connected".into());
    } else {
        verification.push("Mullvad reports NOT connected".into());
    }
    if let Some(true) = connectivity.public_ip.mullvad_exit_ip {
        verification.push("am.i.mullvad.net confirms Mullvad exit IP".into());
    } else if connectivity.public_ip.mullvad_exit_ip == Some(false) {
        verification.push("am.i.mullvad.net says this is NOT a Mullvad exit IP".into());
    }
    if let (Some(a), Some(b)) = (&ip_before.ip, &connectivity.public_ip.ip) {
        if a == b {
            verification.push(format!("public IP stable across checks: {a}"));
        } else {
            verification.push(format!("public IP changed between checks: {a} -> {b}"));
        }
    }
    if connectivity.can_resolve {
        verification.push("DNS resolution works (am.i.mullvad.net)".into());
    } else {
        verification.push("DNS resolution failed for am.i.mullvad.net".into());
    }

    let report = CheckReport {
        before_note: "Captured public IP, then re-verified against Mullvad status + DNS heuristics"
            .into(),
        vpn_status: vpn,
        connectivity,
        dns_heuristics: heuristics,
        verification,
    };

    out.emit_or_human(&report, || {
        let mut s = String::new();
        s.push_str("=== mullvadctl check ===\n");
        s.push_str(&format!("VPN: {}\n", report.vpn_status.state));
        if let Some(ip) = &report.connectivity.public_ip.ip {
            s.push_str(&format!("Public IP: {ip}\n"));
        }
        for v in &report.verification {
            s.push_str(&format!("* {v}\n"));
        }
        s.push_str("\nDNS heuristics:\n");
        for h in &report.dns_heuristics {
            s.push_str(&format!("- {h}\n"));
        }
        s.push_str("\nThese checks are heuristics — not a guarantee of leak-freedom.\n");
        s
    })?;
    Ok(())
}
