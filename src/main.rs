mod args;
mod child;
mod container;
mod sockets;
mod utils;

use args::{setup_logging, Args};
use clap::Parser;

use crate::{
    container::{Container, Error},
    utils::check_linux_version,
};

fn main() -> Result<(), Error> {
    let args = Args::parse();

    setup_logging(args.debug);
    check_linux_version()?;

    log::info!("Running with args: {:?}", args);

    let mut container = Container::new(args)?;
    container.create()?;
    container.wait_for_child()?;
    container.clean_exit()?;

    Ok(())
}
