use crate::mullvad::client;
use crate::session::{clear_session, load_session};
use crate::util::output::OutputOpts;
use crate::util::xdg::XdgPaths;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
struct RestoreResult {
    restored: bool,
    actions: Vec<String>,
    dry_run: bool,
}

pub fn run(out: &OutputOpts, paths: &XdgPaths, dry_run: bool) -> Result<()> {
    let mut actions = Vec::new();
    let session = load_session(paths)?;

    if let Some(s) = &session {
        actions.push(format!(
            "found privacy-session from {} (prev connected={})",
            s.started_at, s.previous_connected
        ));
        if !s.previous_connected {
            if dry_run {
                actions.push("would run: mullvad disconnect".into());
            } else {
                match client::run_mullvad_ok(&["disconnect"]) {
                    Ok(o) => actions.push(format!("disconnect: {}", o.trim())),
                    Err(e) => actions.push(format!("disconnect failed: {e:#}")),
                }
            }
        } else {
            actions.push(
                "previous state was connected — leaving Mullvad connection as-is (use mullvad CLI to adjust)"
                    .into(),
            );
        }
        if dry_run {
            actions.push("would clear privacy-session state file".into());
        } else {
            clear_session(paths)?;
            actions.push("cleared privacy-session state".into());
        }
    } else {
        actions.push("no privacy-session state found".into());
        if dry_run {
            actions.push("would run: mullvad disconnect (best-effort restore)".into());
        } else {
            match client::run_mullvad_ok(&["disconnect"]) {
                Ok(o) => actions.push(format!("disconnect: {}", o.trim())),
                Err(e) => actions.push(format!("disconnect: {e:#}")),
            }
        }
    }

    let result = RestoreResult {
        restored: true,
        actions: actions.clone(),
        dry_run,
    };
    out.emit_or_human(&result, || {
        let mut s = String::from("restore:\n");
        for a in &actions {
            s.push_str(&format!("- {a}\n"));
        }
        s
    })?;
    Ok(())
}
