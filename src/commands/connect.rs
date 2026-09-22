use crate::mullvad::client;
use crate::util::config::AppConfig;
use crate::util::output::OutputOpts;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
struct ConnectResult {
    action: String,
    args: Vec<String>,
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
    let mut args: Vec<String> = vec!["relay".into(), "set".into()];

    if fastest {
        // Mullvad supports location any + closest; "fastest" approximated via location any
        args = vec![
            "relay".into(),
            "set".into(),
            "location".into(),
            "any".into(),
        ];
        out.print_verbose("prefer_fastest / --fastest: setting location any");
    } else if let Some(c) = country.or(cfg.preferred_country.as_deref()) {
        args.push("location".into());
        args.push(c.to_lowercase());
    }

    // After relay set, connect
    let connect_args = vec!["connect".to_string()];

    if dry_run {
        let plan = format!(
            "would run: mullvad {}\nwould run: mullvad {}",
            args.join(" "),
            connect_args.join(" ")
        );
        out.emit_or_human(
            &ConnectResult {
                action: "connect".into(),
                args: args.clone(),
                dry_run: true,
                output: plan.clone(),
            },
            || plan,
        )?;
        return Ok(());
    }

    // Only set relay if we have location args beyond "relay set"
    let mut output = String::new();
    if args.len() > 2 {
        let owned: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match client::run_mullvad_ok(&owned) {
            Ok(o) => {
                output.push_str(&o);
                out.print_verbose(&format!("relay set ok: {o}"));
            }
            Err(e) => {
                out.warn(&format!("relay set skipped/failed: {e:#}"));
            }
        }
    }

    let o = client::run_mullvad_ok(&["connect"])?;
    output.push_str(&o);

    out.emit_or_human(
        &ConnectResult {
            action: "connect".into(),
            args,
            dry_run: false,
            output: output.clone(),
        },
        || format!("Connecting via Mullvad CLI…\n{}", output.trim()),
    )?;
    Ok(())
}
