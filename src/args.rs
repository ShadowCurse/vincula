use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Activate debug mode
    #[arg(short, long)]
    pub debug: bool,

    /// Command to execute inside the container
    #[arg(short, long)]
    pub command: String,

    /// User ID to create inside the container
    #[arg(short, long)]
    pub uid: u32,

    /// Directory to mount as root of the container
    #[arg(short, long)]
    pub mount_dir: PathBuf,
}

pub fn setup_log(level: log::LevelFilter){
    env_logger::Builder::from_default_env()
        .format_timestamp_secs()
        .filter(None, level)
        .init();
}

