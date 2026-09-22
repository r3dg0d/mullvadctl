use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::ToSocketAddrs;
use std::time::Duration;

const DEFAULT_IP_URL: &str = "https://am.i.mullvad.net/json";
const FALLBACK_IP_URL: &str = "https://ifconfig.co/json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PublicIpInfo {
    pub ip: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<String>,
    pub organization: Option<String>,
    pub mullvad_exit_ip: Option<bool>,
    pub source: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsInfo {
    pub resolvers: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectivityReport {
    pub public_ip: PublicIpInfo,
    pub dns: DnsInfo,
    pub ipv6_addresses: Vec<String>,
    pub can_resolve: bool,
}

pub fn fetch_public_ip(url_override: Option<&str>) -> PublicIpInfo {
    let urls: Vec<&str> = match url_override {
        Some(u) => vec![u],
        None => vec![DEFAULT_IP_URL, FALLBACK_IP_URL],
    };
    for url in &urls {
        match fetch_one(url) {
            Ok(info) => return info,
            Err(e) => {
                tracing::debug!("IP check via {url} failed: {e:#}");
                if Some(url) == urls.last() {
                    return PublicIpInfo {
                        source: url.to_string(),
                        error: Some(format!("{e:#}")),
                        ..Default::default()
                    };
                }
            }
        }
    }
    PublicIpInfo {
        source: "none".into(),
        error: Some("all IP check endpoints failed".into()),
        ..Default::default()
    }
}

fn fetch_one(url: &str) -> Result<PublicIpInfo> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(10))
        .build();
    let resp = agent.get(url).call().context("HTTP request")?;
    let v: serde_json::Value = resp.into_json().context("decode JSON")?;

    // am.i.mullvad.net/json shape
    if v.get("mullvad_exit_ip").is_some() || url.contains("am.i.mullvad") {
        return Ok(PublicIpInfo {
            ip: v.get("ip").and_then(|x| x.as_str()).map(str::to_string),
            country: v
                .get("country")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            city: v.get("city").and_then(|x| x.as_str()).map(str::to_string),
            asn: v
                .get("organization")
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .or_else(|| {
                    v.get("blacklisted")
                        .and_then(|_| None::<String>)
                }),
            organization: v
                .get("organization")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            mullvad_exit_ip: v.get("mullvad_exit_ip").and_then(|x| x.as_bool()),
            source: url.to_string(),
            error: None,
        });
    }

    // ifconfig.co/json
    Ok(PublicIpInfo {
        ip: v.get("ip").and_then(|x| x.as_str()).map(str::to_string),
        country: v
            .get("country")
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .or_else(|| {
                v.get("country_iso")
                    .and_then(|x| x.as_str())
                    .map(str::to_string)
            }),
        city: v.get("city").and_then(|x| x.as_str()).map(str::to_string),
        asn: v
            .get("asn")
            .and_then(|x| x.as_str().map(str::to_string).or_else(|| x.as_u64().map(|n| n.to_string()))),
        organization: v
            .get("asn_org")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        mullvad_exit_ip: None,
        source: url.to_string(),
        error: None,
    })
}

pub fn read_dns_resolvers() -> DnsInfo {
    let mut info = DnsInfo::default();
    match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(content) => {
            for line in content.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("nameserver") {
                    let ns = rest.trim();
                    if !ns.is_empty() {
                        info.resolvers.push(ns.to_string());
                    }
                }
            }
            // Heuristics (not definitive leak proof)
            for ns in &info.resolvers {
                if ns == "10.64.0.1" || ns.starts_with("10.64.") {
                    info.notes
                        .push("resolver looks like Mullvad tunnel DNS".into());
                } else if ns == "127.0.0.1" || ns == "::1" {
                    info.notes
                        .push("local stub resolver — verify it does not bypass the tunnel".into());
                } else if ns.starts_with("192.168.") || ns.starts_with("10.") {
                    info.notes.push(format!(
                        "private resolver {ns} — possible LAN/ISP DNS if not tunnel-owned"
                    ));
                }
            }
            if info.resolvers.is_empty() {
                info.notes
                    .push("no nameservers found in /etc/resolv.conf".into());
            }
        }
        Err(e) => {
            info.notes
                .push(format!("could not read /etc/resolv.conf: {e}"));
        }
    }
    info
}

pub fn list_ipv6_addrs() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(output) = std::process::Command::new("ip")
        .args(["-6", "-o", "addr", "show", "scope", "global"])
        .output()
    else {
        return out;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        // format: N: iface    inet6 ADDR/PREFIX ...
        let parts: Vec<_> = line.split_whitespace().collect();
        if let Some(idx) = parts.iter().position(|p| *p == "inet6") {
            if let Some(addr) = parts.get(idx + 1) {
                out.push(addr.to_string());
            }
        }
    }
    out
}

pub fn can_resolve(host: &str) -> bool {
    format!("{host}:443").to_socket_addrs().is_ok()
}

pub fn connectivity_report(url_override: Option<&str>) -> ConnectivityReport {
    ConnectivityReport {
        public_ip: fetch_public_ip(url_override),
        dns: read_dns_resolvers(),
        ipv6_addresses: list_ipv6_addrs(),
        can_resolve: can_resolve("am.i.mullvad.net"),
    }
}

/// Simple DNS leak heuristic: if VPN connected (caller asserts) and resolvers
/// look like common ISP/LAN DNS, flag it.
pub fn dns_leak_heuristics(dns: &DnsInfo, vpn_connected: bool) -> Vec<String> {
    let mut findings = Vec::new();
    if !vpn_connected {
        findings.push("VPN not connected — DNS leak check inconclusive".into());
        return findings;
    }
    for ns in &dns.resolvers {
        if ns.starts_with("192.168.") || ns.starts_with("10.0.") || ns.starts_with("172.16.") {
            findings.push(format!(
                "resolver {ns} looks like LAN/ISP — potential DNS leak path"
            ));
        }
        // Well-known public DNS while on VPN can still be intentional (DoH/DoT)
        if matches!(
            ns.as_str(),
            "8.8.8.8" | "8.8.4.4" | "1.1.1.1" | "1.0.0.1" | "9.9.9.9"
        ) {
            findings.push(format!(
                "public resolver {ns} in use while VPN up — ensure traffic is tunnelled"
            ));
        }
    }
    if findings.is_empty() {
        findings.push("no obvious LAN/public DNS leak heuristics triggered".into());
    }
    findings
}
