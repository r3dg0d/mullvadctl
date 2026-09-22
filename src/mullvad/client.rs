use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// Locate the official `mullvad` CLI binary.
pub fn find_mullvad() -> Result<PathBuf> {
    which("mullvad").with_context(|| {
        "mullvad CLI not found in PATH.\n\
         Install Mullvad VPN from https://mullvad.net/download/vpn/linux\n\
         mullvadctl is a companion helper only — it does not replace Mullvad."
            .to_string()
    })
}

fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let full = dir.join(bin);
            if full.is_file() {
                Some(full)
            } else {
                None
            }
        })
    })
}

pub fn run_mullvad(args: &[&str]) -> Result<Output> {
    let bin = find_mullvad()?;
    let output = Command::new(&bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("failed to execute {} {:?}", bin.display(), args))?;
    Ok(output)
}

pub fn run_mullvad_ok(args: &[&str]) -> Result<String> {
    let output = run_mullvad(args)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "mullvad {} failed (exit {:?}): {}",
            args.join(" "),
            output.status.code(),
            stderr.trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}


/// Optional macrandom dependency.
pub fn run_macrandom_if_present(dry_run: bool) -> Result<Option<String>> {
    let Some(bin) = which("macrandom") else {
        return Ok(None);
    };
    if dry_run {
        return Ok(Some(format!("would run: {} randomize", bin.display())));
    }
    let output = Command::new(&bin)
        .args(["randomize"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("run {}", bin.display()))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        bail!("macrandom failed: {}", combined.trim());
    }
    Ok(Some(combined))
}
