use crate::{viewer::show::Commands, writer::OutputWriter};
use clap::{Parser, ValueEnum, builder};
use log::{LevelFilter, info};
use macos_unifiedlogs::filesystem::{FileProvider, LiveSystemProvider, LogarchiveProvider};
use macos_unifiedlogs::logarchive::{load_timesync_data, visit_live_system, visit_logarchive};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::{fs, io::Write, path::PathBuf};

mod viewer;
mod writer;

#[derive(Parser, Debug)]
struct Args {
    /// Filename to save results to
    #[clap(short, long)]
    output: Option<PathBuf>,

    /// Output format
    #[clap(short, long, default_value = Format::Jsonl)]
    format: Format,

    #[command(subcommand)]
    show: Option<Commands>,
}

#[derive(Parser, Debug, Clone, ValueEnum)]
enum Format {
    Jsonl,
}

impl From<Format> for builder::OsStr {
    fn from(value: Format) -> Self {
        match value {
            Format::Jsonl => "jsonl".into(),
        }
    }
}

impl From<Format> for &str {
    fn from(value: Format) -> Self {
        match value {
            Format::Jsonl => "jsonl",
        }
    }
}

fn main() {
    TermLogger::init(
        LevelFilter::Warn,
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .expect("Failed to initialize simple logger");
    info!("Starting logrs...");

    let args = Args::parse();
    let output_format = args.format;

    let handle: Box<dyn Write> = if let Some(path) = args.output {
        Box::new(
            fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .unwrap(),
        )
    } else {
        Box::new(std::io::stdout())
    };

    let mut writer = OutputWriter::new(Box::new(handle), output_format).unwrap();
    if args.show.is_none() {
        eprintln!("No command option given")
    }
    process_logs(args.show.unwrap(), &mut writer);
    info!("Finishing logrs...");
}

fn process_logs(command: Commands, writer: &mut OutputWriter) {
    match command {
        Commands::Show { archive, timesync } => {
            if archive.is_none() {
                return live(writer, timesync);
            }

            logarchive(archive.unwrap(), writer, timesync)
        }
    }
}

fn live(writer: &mut OutputWriter, only_timesync: bool) {
    if only_timesync {
        let provider = LiveSystemProvider::new();
        let timesync_data =
            load_timesync_data(&provider.timesync_dir()).expect("Could not parse timesync files");
        writer.write_timesync(timesync_data).unwrap();
        return;
    }
    
    let mut index = 0;
    visit_live_system(|entry| {
        writer.write_log(index, &entry).unwrap();
        index += 1;
    })
    .unwrap();
}

fn logarchive(path: PathBuf, writer: &mut OutputWriter, only_timesync: bool) {
    if only_timesync {
        let provider = LogarchiveProvider::new(&path);
        let timesync_data =
            load_timesync_data(&provider.timesync_dir()).expect("Could not parse timesync files");
        writer.write_timesync(timesync_data).unwrap();
        return;
    }

    let mut index = 0;
    visit_logarchive(&path, |entry| {
        writer.write_log(index, &entry).unwrap();
        index += 1;
    })
    .unwrap();
}
