mod args;

use clap::Parser;

use args::{setup_log, Args};

fn main() {
    let args = Args::parse();

    if args.debug {
        setup_log(log::LevelFilter::Debug);
    } else {
        setup_log(log::LevelFilter::Info);
    }

    println!("Hello, world!");
}
