mod alert;
mod capture;
mod detect;
mod rules;

use std::{error::Error, path::PathBuf};

use clap::Parser;

use alert::Webhook;
use detect::Detector;

#[derive(Parser)]
#[command(version, about = "A small rule-based packet monitor")]
struct Args {
    #[arg(long, help = "Network interface to listen on")]
    iface: String,

    #[arg(long, help = "Path to a TOML rules file")]
    rules: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let rules = rules::load(&args.rules)?;
    let webhook = Webhook::from_env()?;

    println!("watchline: {} rules loaded; listening on {}", rules.len(), args.iface);
    println!("Press Ctrl+C to stop.");

    capture::run(&args.iface, Detector::new(rules), webhook)
}
