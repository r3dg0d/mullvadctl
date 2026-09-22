use crate::mullvad::client;
use crate::mullvad::parse::parse_relay_list;
use crate::mullvad::relay::filter_relays;
use crate::util::output::OutputOpts;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
struct RelayListResult {
    count: usize,
    relays: Vec<crate::mullvad::parse::RelayEntry>,
}

pub fn run(
    out: &OutputOpts,
    country: Option<&str>,
    city: Option<&str>,
    provider: Option<&str>,
) -> Result<()> {
    let raw = client::run_mullvad_ok(&["relay", "list"])?;
    let all = parse_relay_list(&raw);
    let filtered: Vec<_> = filter_relays(&all, country, city, provider, false)
        .into_iter()
        .cloned()
        .collect();
    let result = RelayListResult {
        count: filtered.len(),
        relays: filtered.clone(),
    };
    out.emit_or_human(&result, || {
        let mut s = format!("{} relays:\n", result.count);
        for r in &filtered {
            let prov = r.provider.clone().unwrap_or_else(|| "-".into());
            let active = if r.active { "Active" } else { "Inactive" };
            s.push_str(&format!(
                "  {} | {}/{} ({}/{}) | {} | {}\n",
                r.hostname, r.country_code, r.city_code, r.country, r.city, prov, active
            ));
        }
        s
    })?;
    Ok(())
}
