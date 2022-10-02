mod args;
mod config;

use args::{setup_logging, Args};
use clap::Parser;

fn main() {
    let args = Args::parse();
    setup_logging(args.debug);

    println!("Hello, world!");
}
