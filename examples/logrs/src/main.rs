use crate::{viewer::show::Commands, writer::OutputWriter};
use clap::{Parser, ValueEnum, builder};
use macos_unifiedlogs::{
    cache::{StringCatalog, StringStorage},
    filesystem::{LiveSystemProvider, LogarchiveProvider},
    logarchive::{load_timesync_data, visit_live_system, visit_logarchive},
    traits::FileProvider,
};
use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
};
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::{fmt::layer, layer::SubscriberExt, util::SubscriberInitExt};

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
    let log_file =
        File::create(PathBuf::from("issues.jsonl")).expect("Could not create issues.jsonl file");
    let _ = tracing_subscriber::registry()
        .with(
            layer()
                .json()
                .with_file(true)
                .with_line_number(true)
                .with_target(false)
                .flatten_event(true)
                .with_span_list(false)
                .with_writer(log_file),
        )
        .with(LevelFilter::WARN)
        .init();
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
        Commands::Show {
            archive,
            timesync,
            uuidtext,
        } => {
            if archive.is_none() {
                return live(writer, timesync, uuidtext);
            }

            logarchive(archive.unwrap(), writer, timesync, uuidtext)
        }
    }
}

fn live(writer: &mut OutputWriter, only_timesync: bool, only_uuidtext: bool) {
    if only_timesync {
        let provider = LiveSystemProvider::new();
        let timesync_data = load_timesync_data(&provider).expect("Could not parse timesync files");
        writer.write_timesync(timesync_data).unwrap();
        return;
    }

    if only_uuidtext {
        let provider = LiveSystemProvider::new();
        let uuidtext_data = StringStorage::new(&provider);
        uuidtext_data.preload();
        let catalog = StringCatalog::new(&uuidtext_data);

        for uuid in provider.uuidtext_uuids() {
            if let Some(value) = catalog.get_uuidtext(&uuid) {
                writer.write_uuidtext(value).unwrap();
            }
        }

        return;
    }

    let mut index = 0;
    visit_live_system(|entry| {
        writer.write_log(index, &entry).unwrap();
        index += 1;
    })
    .unwrap();
}

fn logarchive(path: PathBuf, writer: &mut OutputWriter, only_timesync: bool, only_uuidtext: bool) {
    if only_timesync {
        let provider = LogarchiveProvider::new(&path);
        let timesync_data = load_timesync_data(&provider).expect("Could not parse timesync files");
        writer.write_timesync(timesync_data).unwrap();
        return;
    }

    if only_uuidtext {
        let provider = LiveSystemProvider::new();
        let uuidtext_data = StringStorage::new(&provider);
        uuidtext_data.preload();
        let catalog = StringCatalog::new(&uuidtext_data);

        for uuid in provider.uuidtext_uuids() {
            if let Some(value) = catalog.get_uuidtext(&uuid) {
                writer.write_uuidtext(value).unwrap();
            }
        }
    }

    let mut index = 0;
    visit_logarchive(&path, |entry| {
        writer.write_log(index, &entry).unwrap();
        index += 1;
    })
    .unwrap();
}
