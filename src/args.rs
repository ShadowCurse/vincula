use std::path::PathBuf;

use clap::Parser;

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

    /// Additional directories to mount
    #[arg(short, long)]
    pub additional_mounts: Vec<String>,

    /// Hostname of the container
    #[arg(long)]
    pub hostname: String,
}
