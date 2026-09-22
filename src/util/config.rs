use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    /// Preferred country code for connect/rotate (e.g. "se").
    pub preferred_country: Option<String>,
    /// Prefer fastest relay when rotating.
    pub prefer_fastest: bool,
    /// Optional override for public IP check URL.
    pub ip_check_url: Option<String>,
    /// Call macrandom if installed during privacy-session.
    pub use_macrandom: bool,
}

impl AppConfig {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        // Minimal TOML-ish: support JSON for simplicity if file is JSON; else defaults + key parsing
        if path.extension().and_then(|e| e.to_str()) == Some("json") || raw.trim_start().starts_with('{') {
            let cfg: Self = serde_json::from_str(&raw)
                .with_context(|| format!("parse config {}", path.display()))?;
            return Ok(cfg);
        }
        // Very small TOML subset without adding toml dep: key = value lines
        let mut cfg = Self::default();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let k = k.trim();
            let v = v.trim().trim_matches('"').trim_matches('\'');
            match k {
                "preferred_country" => cfg.preferred_country = Some(v.to_string()),
                "prefer_fastest" => cfg.prefer_fastest = v == "true" || v == "1",
                "ip_check_url" => cfg.ip_check_url = Some(v.to_string()),
                "use_macrandom" => cfg.use_macrandom = v == "true" || v == "1",
                _ => {}
            }
        }
        Ok(cfg)
    }
}
