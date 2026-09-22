use crate::util::xdg::XdgPaths;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SavedSession {
    pub started_at: String,
    pub previous_relay: Option<String>,
    pub previous_connected: bool,
    pub previous_public_ip: Option<String>,
    pub macrandom_invoked: bool,
    pub notes: Vec<String>,
}

pub fn session_path(paths: &XdgPaths) -> PathBuf {
    paths.session_file()
}

pub fn save_session(paths: &XdgPaths, session: &SavedSession) -> Result<()> {
    paths.ensure_all()?;
    let path = session_path(paths);
    let data = serde_json::to_string_pretty(session)?;
    fs::write(&path, data).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

pub fn load_session(paths: &XdgPaths) -> Result<Option<SavedSession>> {
    let path = session_path(paths);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let s: SavedSession = serde_json::from_str(&data)?;
    Ok(Some(s))
}

pub fn clear_session(paths: &XdgPaths) -> Result<()> {
    let path = session_path(paths);
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}
