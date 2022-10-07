mod args;
mod container;
mod sockets;

use args::{setup_logging, Args};
use clap::Parser;
use container::{Error, check_linux_version};

use crate::container::Container;

fn main() -> Result<(), Error> {
    let args = Args::parse();

    setup_logging(args.debug);
    check_linux_version()?;

    let mut container = Container::new(args)?;
    container.create()?;
    container.clean_exit()?;

    Ok(())
}
