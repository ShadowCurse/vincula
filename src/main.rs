mod args;
mod child;
mod container;
mod sockets;
mod utils;

use args::Args;
use clap::Parser;
use log::error;
use utils::setup_logging;

use crate::{
    container::{Container, Error},
    utils::check_linux_version,
};

fn main() {
    match actual_main() {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e)
        }
    }
}

fn actual_main() -> Result<(), Error> {
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
