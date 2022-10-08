mod args;
mod container;
mod sockets;

use args::{setup_logging, Args};
use clap::Parser;
use container::{check_linux_version, Error};

use crate::container::Container;

fn main() -> Result<(), Error> {
    let args = Args::parse();

    setup_logging(args.debug);
    check_linux_version()?;

    let mut container = Container::new(args)?;
    container.create()?;
    container.wait_for_child()?;
    container.clean_exit()?;

    Ok(())
}
