mod cli;
mod crypto;
mod storage;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    
    if let Err(err) = cli::run_cli(cli) {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}