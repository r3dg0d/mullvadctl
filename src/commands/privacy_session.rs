use crate::mullvad::client;
use crate::mullvad::parse::parse_status;
use crate::net::check::fetch_public_ip;
use crate::session::{clear_session, save_session, SavedSession};
use crate::util::config::AppConfig;
use crate::util::output::OutputOpts;
use crate::util::xdg::XdgPaths;
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Serialize)]
struct SessionLive {
    status: String,
    exit_ip: Option<String>,
    mullvad_exit: Option<bool>,
    notes: Vec<String>,
}

pub fn run(out: &OutputOpts, cfg: &AppConfig, paths: &XdgPaths, dry_run: bool) -> Result<()> {
    paths.ensure_all()?;
    let raw = client::run_mullvad_ok(&["status"])?;
    let before = parse_status(&raw);
    let ip_before = fetch_public_ip(cfg.ip_check_url.as_deref());

    let mut notes = Vec::new();
    notes.push("privacy-session remembers prior VPN state and restores on end".into());

    if cfg.use_macrandom {
        match client::run_macrandom_if_present(dry_run)? {
            Some(msg) => notes.push(format!("macrandom: {}", msg.trim())),
            None => notes.push("macrandom not installed — skipped (optional)".into()),
        }
    } else {
        notes.push("use_macrandom=false — not invoking macrandom".into());
    }

    if dry_run {
        notes.push("dry-run: would connect Mullvad, verify tunnel, wait for Ctrl+C, then restore".into());
        out.emit_or_human(
            &SessionLive {
                status: "dry-run".into(),
                exit_ip: ip_before.ip,
                mullvad_exit: ip_before.mullvad_exit_ip,
                notes: notes.clone(),
            },
            || {
                let mut s = String::from("privacy-session (dry-run):\n");
                for n in &notes {
                    s.push_str(&format!("- {n}\n"));
                }
                s
            },
        )?;
        return Ok(());
    }

    let session = SavedSession {
        started_at: Utc::now().to_rfc3339(),
        previous_relay: before.relay.clone(),
        previous_connected: before.connected,
        previous_public_ip: ip_before.ip.clone(),
        macrandom_invoked: cfg.use_macrandom,
        notes: notes.clone(),
    };
    save_session(paths, &session)?;

    // Connect
    let _ = client::run_mullvad_ok(&["connect"])?;
    // Brief wait for tunnel
    thread::sleep(Duration::from_secs(2));
    let after_status = parse_status(&client::run_mullvad_ok(&["status"])?);
    let after_ip = fetch_public_ip(cfg.ip_check_url.as_deref());

    let mut live_notes = notes.clone();
    live_notes.push(format!("tunnel state now: {}", after_status.state));
    if let Some(ip) = &after_ip.ip {
        live_notes.push(format!("exit IP: {ip}"));
    }
    match after_ip.mullvad_exit_ip {
        Some(true) => live_notes.push("verified Mullvad exit IP".into()),
        Some(false) => live_notes.push("WARNING: not a Mullvad exit IP".into()),
        None => live_notes.push("could not confirm mullvad_exit_ip flag".into()),
    }
    live_notes.push("Press Ctrl+C to end session and restore…".into());

    out.emit_or_human(
        &SessionLive {
            status: after_status.state.clone(),
            exit_ip: after_ip.ip.clone(),
            mullvad_exit: after_ip.mullvad_exit_ip,
            notes: live_notes.clone(),
        },
        || {
            let mut s = String::from("privacy-session active:\n");
            for n in &live_notes {
                s.push_str(&format!("- {n}\n"));
            }
            s
        },
    )?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(200));
    }

    // Restore
    out.print_human("Ending privacy-session — restoring…");
    if !session.previous_connected {
        let _ = client::run_mullvad_ok(&["disconnect"]);
    }
    clear_session(paths)?;
    out.print_human("privacy-session ended.");
    Ok(())
}
