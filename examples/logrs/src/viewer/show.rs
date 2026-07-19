use std::path::PathBuf;
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    /// View log messages
    Show {
        /// Optional path to logarchive
        #[clap(long)]
        archive: Option<PathBuf>,
        /// Only output timesync data
        #[clap(long)]
        timesync:bool,
        // Parse specific tracev3 log files
        //#[clap(long, value_delimiter = ',')]
        //trace_files:Option<Vec<PathBuf>>
        
    },
}
