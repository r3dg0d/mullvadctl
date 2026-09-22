use serde::Serialize;
use std::io::{self, Write};

#[derive(Clone, Copy, Debug)]
pub struct OutputOpts {
    pub json: bool,
    pub quiet: bool,
    pub verbose: bool,
}

impl OutputOpts {
    pub fn print_human(&self, msg: &str) {
        if !self.json && !self.quiet {
            println!("{msg}");
        }
    }

    pub fn print_verbose(&self, msg: &str) {
        if self.verbose && !self.quiet {
            eprintln!("[verbose] {msg}");
        }
    }

    pub fn emit<T: Serialize>(&self, value: &T) -> anyhow::Result<()> {
        if self.json {
            serde_json::to_writer_pretty(io::stdout(), value)?;
            println!();
        }
        Ok(())
    }

    pub fn emit_or_human<T: Serialize>(&self, value: &T, human: impl FnOnce() -> String) -> anyhow::Result<()> {
        if self.json {
            self.emit(value)?;
        } else if !self.quiet {
            println!("{}", human());
        }
        Ok(())
    }

    pub fn warn(&self, msg: &str) {
        if !self.quiet {
            let _ = writeln!(io::stderr(), "warning: {msg}");
        }
    }
}
