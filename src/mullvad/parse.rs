use serde::{Deserialize, Serialize};

/// Parsed view of `mullvad status` human output (best-effort).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MullvadStatus {
    pub connected: bool,
    pub state: String,
    pub relay: Option<String>,
    pub location: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub tunnel_type: Option<String>,
    pub features: Vec<String>,
    pub raw: String,
}

/// Parse `mullvad status` text into a structured summary.
/// Tolerant of format drift — prefers extraction over perfect fidelity.
pub fn parse_status(raw: &str) -> MullvadStatus {
    let mut st = MullvadStatus {
        raw: raw.to_string(),
        state: "unknown".into(),
        ..Default::default()
    };

    let lower = raw.to_lowercase();
    st.connected = lower.contains("connected") && !lower.contains("disconnected");

    for line in raw.lines() {
        let line = line.trim();
        let ll = line.to_lowercase();
        if ll.starts_with("connected") {
            st.state = "Connected".into();
            st.connected = true;
        } else if ll.starts_with("disconnected") {
            st.state = "Disconnected".into();
            st.connected = false;
        } else if ll.starts_with("connecting") {
            st.state = "Connecting".into();
        } else if let Some(rest) = strip_prefix_ci(line, "Relay:") {
            st.relay = Some(rest.trim().to_string());
        } else if let Some(rest) = strip_prefix_ci(line, "Location:") {
            st.location = Some(rest.trim().to_string());
        } else if let Some(rest) = strip_prefix_ci(line, "IPv4:") {
            st.ipv4 = Some(rest.trim().to_string());
        } else if let Some(rest) = strip_prefix_ci(line, "IPv6:") {
            st.ipv6 = Some(rest.trim().to_string());
        } else if let Some(rest) = strip_prefix_ci(line, "Tunnel protocol:") {
            st.tunnel_type = Some(rest.trim().to_string());
        } else if ll.contains("wireguard") {
            if st.tunnel_type.is_none() {
                st.tunnel_type = Some("WireGuard".into());
            }
        } else if ll.contains("kill switch") || ll.contains("lockdown") || ll.contains("quantum") {
            st.features.push(line.to_string());
        }
    }

    if st.state == "unknown" {
        if st.connected {
            st.state = "Connected".into();
        } else if lower.contains("disconnected") {
            st.state = "Disconnected".into();
        }
    }
    st
}

fn strip_prefix_ci<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    if line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&line[prefix.len()..])
    } else {
        None
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayEntry {
    pub hostname: String,
    pub country_code: String,
    pub country: String,
    pub city_code: String,
    pub city: String,
    pub provider: Option<String>,
    pub active: bool,
}

/// Parse `mullvad relay list` output (hierarchical human format).
pub fn parse_relay_list(raw: &str) -> Vec<RelayEntry> {
    let mut out = Vec::new();
    let mut country = String::new();
    let mut country_code = String::new();
    let mut city = String::new();
    let mut city_code = String::new();

    // Patterns like:
    // Sweden (se)
    //   Gothenburg (got)
    //       se-got-wg-001 (Active) using WireGuard...
    let country_re = regex::Regex::new(r"^([-A-Za-z .']+)\s*\(([a-z]{2})\)\s*$").unwrap();
    let city_re = regex::Regex::new(r"^\s+([-A-Za-z .']+)\s*\(([a-z]{3})\)\s*$").unwrap();
    let host_re = regex::Regex::new(
        r"^\s*([a-z]{2}-[a-z0-9-]+)\s*\((Active|Inactive)\)(?:.*?hosted by ([A-Za-z0-9._-]+))?",
    )
    .unwrap();

    for line in raw.lines() {
        let line = line.trim_end();
        if let Some(c) = host_re.captures(line) {
            out.push(RelayEntry {
                hostname: c[1].to_string(),
                country_code: country_code.clone(),
                country: country.clone(),
                city_code: city_code.clone(),
                city: city.clone(),
                provider: c.get(3).map(|m| m.as_str().to_string()),
                active: &c[2] == "Active",
            });
            continue;
        }
        if let Some(c) = city_re.captures(line) {
            city = c[1].trim().to_string();
            city_code = c[2].to_string();
            continue;
        }
        if let Some(c) = country_re.captures(line.trim_start()) {
            country = c[1].trim().to_string();
            country_code = c[2].to_string();
            continue;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connected_status() {
        let raw = "Connected to se-mma-wg-001 in Stockholm, Sweden\n\
                   Relay: se-mma-wg-001\n\
                   Tunnel protocol: WireGuard\n\
                   Features: Multihop, LAN sharing\n\
                   IPv4: 193.138.218.50\n\
                   IPv6: —\n";
        let st = parse_status(raw);
        assert!(st.connected);
        assert_eq!(st.relay.as_deref(), Some("se-mma-wg-001"));
        assert_eq!(st.ipv4.as_deref(), Some("193.138.218.50"));
        assert_eq!(st.tunnel_type.as_deref(), Some("WireGuard"));
    }

    #[test]
    fn parse_disconnected_status() {
        let raw = "Disconnected\n";
        let st = parse_status(raw);
        assert!(!st.connected);
        assert_eq!(st.state, "Disconnected");
    }

        #[test]
    fn parse_relays() {
        let raw = r#"Sweden (se)
  Gothenburg (got)
      se-got-wg-001 (Active) using WireGuard, hosted by 31173
      se-got-wg-002 (Inactive) using WireGuard, hosted by 31173
Germany (de)
  Berlin (ber)
      de-ber-wg-001 (Active) using WireGuard, hosted by DataCamp
"#;
        let relays = parse_relay_list(raw);
        assert_eq!(relays.len(), 3);
        assert_eq!(relays[0].hostname, "se-got-wg-001");
        assert_eq!(relays[0].country_code, "se");
        assert_eq!(relays[0].city_code, "got");
        assert_eq!(relays[0].provider.as_deref(), Some("31173"));
        assert!(relays[0].active);
        assert!(!relays[1].active);
        assert_eq!(relays[2].country_code, "de");
    }
}
