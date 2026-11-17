use clap::{Args, Parser, Subcommand};
use hyperrev_loader::app::{Operation, SetupInput, default_input, perform};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    version,
    about = "hyper-reV and Safe Windows UEFI setup; original boot entries and Windows boot files are preserved"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read firmware boot state without changing boot variables or ESP files.
    Inspect,
    /// Find bundled payloads, save recovery state, and configure both entries in one operation.
    Setup {
        #[arg(long)]
        source: Option<PathBuf>,
        #[arg(long)]
        reference: Option<String>,
        #[command(flatten)]
        paths: Paths,
    },
    /// Validate payloads and save a fresh, immutable recovery journal.
    Plan {
        /// Directory containing uefi-boot-standalone.efi and hyperv-attachment.dll.
        #[arg(long)]
        source: PathBuf,
        /// A verified stock Windows firmware option, such as Boot0000.
        #[arg(long)]
        reference: Option<String>,
        #[command(flatten)]
        paths: Paths,
    },
    /// Stage files and install persistent hyper-reV and Safe Windows firmware entries.
    Apply {
        #[command(flatten)]
        paths: Paths,
    },
    /// Restore the original boot order and remove only this journal's entries and new files.
    Restore {
        #[command(flatten)]
        paths: Paths,
    },
}

#[derive(Args)]
struct Paths {
    /// Mounted ESP root; omission temporarily mounts the system ESP.
    #[arg(long)]
    esp: Option<PathBuf>,
    /// Recovery journal; defaults to LOCALAPPDATA/hyper-reV/boot-install.json.
    #[arg(long)]
    journal: Option<PathBuf>,
}

impl Paths {
    fn input(self) -> SetupInput {
        let mut input = default_input();
        input.esp = self.esp;
        if let Some(path) = self.journal {
            input.journal = path;
        }
        input
    }
}

fn main() -> ExitCode {
    let (operation, input) = match Cli::parse().command {
        Command::Inspect => (Operation::Inspect, default_input()),
        Command::Setup {
            source,
            reference,
            paths,
        } => {
            let mut input = paths.input();
            if let Some(source) = source {
                input.source = source;
            }
            input.reference = reference;
            (Operation::Setup, input)
        }
        Command::Plan {
            source,
            reference,
            paths,
        } => {
            let mut input = paths.input();
            input.source = source;
            input.reference = reference;
            (Operation::Plan, input)
        }
        Command::Apply { paths } => (Operation::Apply, paths.input()),
        Command::Restore { paths } => (Operation::Restore, paths.input()),
    };
    match perform(operation, input) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("hyper-reV setup: {error:#}");
            ExitCode::FAILURE
        }
    }
}
