use crate::mullvad::client;
use crate::mullvad::parse::parse_status;
use crate::net::check::{connectivity_report, dns_leak_heuristics};
use crate::util::config::AppConfig;
use crate::util::output::OutputOpts;
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

#[derive(Serialize)]
struct OpsecReport {
    generated_at: String,
    disclaimer: String,
    vpn: crate::mullvad::parse::MullvadStatus,
    network: crate::net::check::ConnectivityReport,
    dns_heuristics: Vec<String>,
    recommendations: Vec<String>,
}

pub fn run(out: &OutputOpts, cfg: &AppConfig) -> Result<()> {
    let raw = client::run_mullvad_ok(&["status"])?;
    let vpn = parse_status(&raw);
    let network = connectivity_report(cfg.ip_check_url.as_deref());
    let dns_heuristics = dns_leak_heuristics(&network.dns, vpn.connected);

    let mut recommendations = vec![
        "Prefer official Mullvad app/CLI for all security-critical settings.".into(),
        "Enable lockdown mode when you need fail-closed networking.".into(),
        "Verify exit IP on https://am.i.mullvad.net after connect/rotate.".into(),
        "Avoid mixing system-wide DoH with VPN DNS unless you understand the trust model.".into(),
    ];
    if !vpn.connected {
        recommendations.insert(
            0,
            "VPN is disconnected — connect before relying on tunnel privacy.".into(),
        );
    }
    if !network.ipv6_addresses.is_empty() && vpn.connected {
        recommendations.push(
            "Global IPv6 addresses present — ensure Mullvad IPv6/tunnel policy matches your threat model."
                .into(),
        );
    }

    let report = OpsecReport {
        generated_at: Utc::now().to_rfc3339(),
        disclaimer: "OPSEC-style informational report from mullvadctl companion helper. Not a penetration test."
            .into(),
        vpn,
        network,
        dns_heuristics,
        recommendations,
    };

    out.emit_or_human(&report, || {
        let mut s = String::new();
        s.push_str(&format!("mullvadctl OPSEC report @ {}\n", report.generated_at));
        s.push_str(&format!("{}\n\n", report.disclaimer));
        s.push_str(&format!("VPN state: {}\n", report.vpn.state));
        if let Some(r) = &report.vpn.relay {
            s.push_str(&format!("Relay: {r}\n"));
        }
        if let Some(ip) = &report.network.public_ip.ip {
            s.push_str(&format!("Exit/public IP: {ip}\n"));
        }
        s.push_str(&format!(
            "DNS resolvers: {}\n",
            report.network.dns.resolvers.join(", ")
        ));
        s.push_str("\nHeuristics:\n");
        for h in &report.dns_heuristics {
            s.push_str(&format!("- {h}\n"));
        }
        s.push_str("\nRecommendations:\n");
        for r in &report.recommendations {
            s.push_str(&format!("* {r}\n"));
        }
        s
    })?;
    Ok(())
}
