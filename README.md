# mullvadctl

**Companion CLI helper for [Mullvad VPN](https://mullvad.net/)** — convenience wrappers around the official `mullvad` binary plus public IP / DNS checks.

> **Important:** `mullvadctl` does **not** replace, reimplement, or weaken Mullvad security.  
> All tunnel cryptography, kill-switch, and lockdown behaviour remain owned by the official Mullvad client.  
> If the `mullvad` binary is missing, this tool refuses to pretend it can protect you.

Owner: **r3dg0d** · License: **MIT**

## Features

| Command | Purpose |
|---------|---------|
| `status` | VPN state, relay, exit IP, country/city/ASN (when available), DNS, IPv6, WG/kill-switch/lockdown hints |
| `connect` | `connect`, `connect --country se`, `connect --fastest` |
| `rotate` | Random or fastest/any relay rotation |
| `check` | Connectivity + public IP before/after-style verification + DNS leak **heuristics** |
| `report` | OPSEC-style informational network report |
| `restore` | Restore state remembered by `privacy-session` |
| `privacy-session` | Snapshot state → optional `macrandom` → connect → verify → restore on Ctrl+C / `restore` |
| `relay` | Browse/filter `mullvad relay list` by country/city/provider |
| `completions` | Shell completions (bash/zsh/fish/powershell/elvish) |

Global flags: `--json` `--verbose` `--quiet` `--config` `--dry-run` `--help` `--version`

## Requirements

- Official **Mullvad VPN** app / CLI (`mullvad` on `PATH`)  
  Install: https://mullvad.net/download/vpn/linux
- Linux (primary target)
- Optional: [`macrandom`](https://github.com/r3dg0d/macrandom) for MAC randomisation during `privacy-session`

## Install

```bash
cargo install --path .
# or
nix build
```

## Usage

```bash
mullvadctl status
mullvadctl connect --country se
mullvadctl connect --fastest
mullvadctl rotate
mullvadctl check --json
mullvadctl report
mullvadctl relay --country se --city got
mullvadctl privacy-session
mullvadctl restore
mullvadctl completions bash > ~/.local/share/bash-completion/completions/mullvadctl
```

### Config (XDG)

Default config path: `$XDG_CONFIG_HOME/mullvadctl/config.toml`  
(or `~/.config/mullvadctl/config.toml`)

```toml
preferred_country = "se"
prefer_fastest = false
use_macrandom = true
# ip_check_url = "https://am.i.mullvad.net/json"
```

JSON configs are also accepted.

State for privacy sessions: `$XDG_STATE_HOME/mullvadctl/privacy-session.json`

## Security model (honest)

- Shells out to `mullvad` — never talks WireGuard keys itself
- Public IP checks use `https://am.i.mullvad.net/json` (fallback `ifconfig.co`)
- DNS “leak” findings are **heuristics**, not proofs
- Does not disable Mullvad lockdown/kill-switch
- Fail closed when `mullvad` is absent (clear install message, exit code 2)

## Development

```bash
cargo test
cargo build --release
cargo run -- --help
```

Integration paths that need a live Mullvad daemon are skipped/fail clearly when `mullvad` is absent. Parser unit tests do not require Mullvad.

## Disclaimer

This is a helper for operators who already use Mullvad. It is not a VPN product.
