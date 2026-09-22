use crate::mullvad::client;
use crate::mullvad::parse::parse_relay_list;
use crate::mullvad::relay::filter_relays;
use crate::util::config::AppConfig;
use crate::util::output::OutputOpts;
use anyhow::{bail, Result};
use rand::seq::SliceRandom;
use serde::Serialize;

#[derive(Serialize)]
struct RotateResult {
    selected: Option<String>,
    mode: String,
    dry_run: bool,
    output: String,
}

pub fn run(
    out: &OutputOpts,
    cfg: &AppConfig,
    country: Option<&str>,
    fastest: bool,
    dry_run: bool,
) -> Result<()> {
    if fastest || cfg.prefer_fastest {
        let args = ["relay", "set", "location", "any"];
        if dry_run {
            let msg = format!("would run: mullvad {}\nwould run: mullvad reconnect", args.join(" "));
            out.emit_or_human(
                &RotateResult {
                    selected: None,
                    mode: "fastest/any".into(),
                    dry_run: true,
                    output: msg.clone(),
                },
                || msg,
            )?;
            return Ok(());
        }
        let _ = client::run_mullvad_ok(&args)?;
        let o = client::run_mullvad_ok(&["reconnect"]).or_else(|_| client::run_mullvad_ok(&["connect"]))?;
        out.emit_or_human(
            &RotateResult {
                selected: None,
                mode: "fastest/any".into(),
                dry_run: false,
                output: o.clone(),
            },
            || format!("Rotated to any/closest location.\n{}", o.trim()),
        )?;
        return Ok(());
    }

    let list = client::run_mullvad_ok(&["relay", "list"])?;
    let relays = parse_relay_list(&list);
    let country = country.or(cfg.preferred_country.as_deref());
    let filtered = filter_relays(&relays, country, None, None, true);
    if filtered.is_empty() {
        bail!("no active relays matched filters");
    }
    let mut rng = rand::thread_rng();
    let pick = filtered.choose(&mut rng).unwrap();
    let host = pick.hostname.clone();

    if dry_run {
        let msg = format!("would run: mullvad relay set location {} {}\nwould reconnect", pick.country_code, pick.city_code);
        out.emit_or_human(
            &RotateResult {
                selected: Some(host),
                mode: "random".into(),
                dry_run: true,
                output: msg.clone(),
            },
            || msg,
        )?;
        return Ok(());
    }

    // Prefer hostname set if supported; fall back to location
    let set_result = client::run_mullvad_ok(&["relay", "set", "location", &pick.country_code, &pick.city_code, &pick.hostname])
        .or_else(|_| {
            client::run_mullvad_ok(&["relay", "set", "location", &pick.country_code, &pick.city_code])
        })?;
    let o = client::run_mullvad_ok(&["reconnect"]).or_else(|_| client::run_mullvad_ok(&["connect"]))?;
    let output = format!("{set_result}{o}");
    out.emit_or_human(
        &RotateResult {
            selected: Some(host.clone()),
            mode: "random".into(),
            dry_run: false,
            output: output.clone(),
        },
        || format!("Rotated toward {host}\n{}", output.trim()),
    )?;
    Ok(())
}
