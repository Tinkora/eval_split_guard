use clap::{error::ErrorKind, Parser, Subcommand};
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
        #[arg(long = "leakage-pair", required = true, value_parser = parse_pair)]
        leakage_pairs: Vec<(String, String)>,
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
}

fn main() {
    let json_requested = json_format_requested();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            error.exit()
        }
        Err(_) if json_requested => exit_incomplete_json(),
        Err(error) => error.exit(),
    };
    let (format, result) = match cli.command {
        Command::Audit {
            input,
            leakage_pairs,
            format,
        } => (
            format,
            audit(&input, &AuditOptions { leakage_pairs })
                .and_then(|report| render(&report, format).map(|output| (report, output))),
        ),
    };
    match result {
        Ok((report, output)) => {
            println!("{output}");
            std::process::exit(i32::from(!report.findings.is_empty()));
        }
        Err(error) => {
            if matches!(format, OutputFormat::Json) {
                exit_incomplete_json();
            } else {
                eprintln!("eval_split_guard: {error:#}");
                std::process::exit(2);
            }
        }
    }
}

fn json_format_requested() -> bool {
    let arguments: Vec<_> = std::env::args_os().collect();
    arguments.iter().any(|argument| argument == "--format=json")
        || arguments
            .windows(2)
            .any(|pair| pair[0] == "--format" && pair[1] == "json")
}

fn exit_incomplete_json() -> ! {
    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "kind": "eval_split_guard",
            "complete": false,
            "error_code": "incomplete_audit",
            "message": "Audit could not be completed because input or resource validation failed"
        })
    );
    std::process::exit(2);
}
