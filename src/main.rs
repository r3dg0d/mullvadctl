mod commands;
mod mullvad;
mod net;
mod session;
mod util;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use std::io;
use std::path::PathBuf;
use util::config::AppConfig;
use util::output::OutputOpts;
use util::xdg::XdgPaths;

#[derive(Parser, Debug)]
#[command(
    name = "mullvadctl",
    author = "r3dg0d",
    version,
    about = "Companion helper for the official Mullvad CLI — never replaces or weakens Mullvad security",
    long_about = "mullvadctl shells out to the official `mullvad` binary and adds convenience \
status/check/report/privacy-session workflows.\n\n\
This is NOT a VPN client and must not be used as a substitute for Mullvad."
)]
struct Cli {
    /// Emit machine-readable JSON
    #[arg(long, global = true)]
    json: bool,

    /// Verbose logging
    #[arg(long, short = 'v', global = true)]
    verbose: bool,

    /// Suppress non-essential output
    #[arg(long, short = 'q', global = true)]
    quiet: bool,

    /// Path to config file (JSON or simple key=value)
    #[arg(long, global = true, env = "MULLVADCTL_CONFIG")]
    config: Option<PathBuf>,

    /// Show what would happen without making changes
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show VPN state, relay, exit IP, DNS, IPv6, and related hints
    Status,
    /// Connect via official mullvad CLI
    Connect {
        /// Country code or name (e.g. se)
        #[arg(long)]
        country: Option<String>,
        /// Prefer any/closest location (fastest approximation)
        #[arg(long)]
        fastest: bool,
    },
    /// Rotate to a random or fastest relay
    Rotate {
        #[arg(long)]
        country: Option<String>,
        #[arg(long)]
        fastest: bool,
    },
    /// Connectivity + public IP verification + DNS leak heuristics
    Check,
    /// OPSEC-style network report
    Report,
    /// Restore network/session state from privacy-session
    Restore,
    /// Remember state, optionally macrandom, connect, verify, restore on Ctrl+C
    #[command(name = "privacy-session")]
    PrivacySession,
    /// Browse/filter relays from `mullvad relay list`
    Relay {
        #[arg(long)]
        country: Option<String>,
        #[arg(long)]
        city: Option<String>,
        #[arg(long)]
        provider: Option<String>,
    },
    /// Generate shell completions
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn init_tracing(verbose: bool, quiet: bool) {
    let level = if quiet {
        "error"
    } else if verbose {
        "debug"
    } else {
        "info"
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.quiet);

    let out = OutputOpts {
        json: cli.json,
        quiet: cli.quiet,
        verbose: cli.verbose,
    };

    if let Commands::Completions { shell } = cli.command {
        let mut cmd = Cli::command();
        generate(shell, &mut cmd, "mullvadctl", &mut io::stdout());
        return Ok(());
    }

    // All other commands need mullvad present (except we still fail clearly)
    if !matches!(cli.command, Commands::Completions { .. }) {
        // find early for clear error (completions already returned)
        if let Err(e) = mullvad::client::find_mullvad() {
            // allow --help already handled by clap; for dry-run of docs we still error
            // Completions handled above.
            eprintln!("{e:#}");
            // For unit tests / environments without mullvad, still exit non-zero as required
            std::process::exit(2);
        }
    }

    let paths = XdgPaths::new()?;
    let cfg_path = cli
        .config
        .clone()
        .unwrap_or_else(|| paths.default_config_file());
    let cfg = AppConfig::load(Some(&cfg_path))?;

    match cli.command {
        Commands::Status => commands::status::run(&out, &cfg)?,
        Commands::Connect { country, fastest } => {
            commands::connect::run(&out, &cfg, country.as_deref(), fastest, cli.dry_run)?
        }
        Commands::Rotate { country, fastest } => {
            commands::rotate::run(&out, &cfg, country.as_deref(), fastest, cli.dry_run)?
        }
        Commands::Check => commands::check::run(&out, &cfg)?,
        Commands::Report => commands::report::run(&out, &cfg)?,
        Commands::Restore => commands::restore::run(&out, &paths, cli.dry_run)?,
        Commands::PrivacySession => {
            commands::privacy_session::run(&out, &cfg, &paths, cli.dry_run)?
        }
        Commands::Relay {
            country,
            city,
            provider,
        } => commands::relay::run(&out, country.as_deref(), city.as_deref(), provider.as_deref())?,
        Commands::Completions { .. } => unreachable!(),
    }
    Ok(())
}
