use clap::{Parser, Subcommand};
use eval_split_guard::{audit, parse_pair, render, AuditOptions, OutputFormat};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Audit {
        input: PathBuf,
        #[arg(long = "pair", required = true, value_parser = parse_pair)]
        leakage_pairs: Vec<(String, String)>,
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
}

fn main() {
    let result = match Cli::parse().command {
        Command::Audit {
            input,
            leakage_pairs,
            format,
        } => audit(&input, &AuditOptions { leakage_pairs })
            .and_then(|report| render(&report, format).map(|output| (report, output))),
    };
    match result {
        Ok((report, output)) => {
            println!("{output}");
            std::process::exit(i32::from(!report.findings.is_empty()));
        }
        Err(error) => {
            eprintln!("eval_split_guard: {error:#}");
            std::process::exit(2);
        }
    }
}
