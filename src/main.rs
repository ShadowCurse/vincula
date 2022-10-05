mod args;
mod container;

use args::{setup_logging, Args};
use clap::Parser;
use container::Error;

use crate::container::Container;

fn main() -> Result<(), Error> {
    let args = Args::parse();

    setup_logging(args.debug);

    let mut container = Container::new(args)?;
    container.create()?;
    container.clean_exit()?;

    Ok(())
}
