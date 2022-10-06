use std::ffi::CString;
use std::path::PathBuf;

use nix::errno::Errno;
use nix::sys::utsname::uname;
use scan_fmt::{parse::ScanError, scan_fmt};

use crate::args::Args;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    #[error("No binary path provided in the commands")]
    NoBinayPath,
    #[error("Unsupported kernel version")]
    UnsupportedKernelVersion,
    #[error("Unsupported architecture")]
    UnsupportedArchitecture,
    #[error("Error while getting system info: {0}")]
    SystemInfoError(Errno),
    #[error("Error while scanning system info: {0}")]
    SystemInfoScanError(ScanError),
}

#[derive(Debug, Clone)]
pub struct ContainerConfig {
    pub binary_path: CString,
    pub argv: Vec<CString>,

    pub uid: u32,
    pub mount_dir: PathBuf,
}

impl ContainerConfig {
    pub fn new(command: String, uid: u32, mount_dir: PathBuf) -> Result<Self, Error> {
        let argv = command
            .split_ascii_whitespace()
            .map(|s| CString::new(s).expect("Cannot read arg"))
            .collect::<Vec<_>>();

        if argv.is_empty() {
            return Err(Error::NoBinayPath);
        }

        let binary_path = argv[0].clone();

        Ok(Self {
            binary_path,
            argv,
            uid,
            mount_dir,
        })
    }
}

pub struct Container {
    config: ContainerConfig,
}

impl Container {
    pub fn new(args: Args) -> Result<Container, Error> {
        let config = ContainerConfig::new(args.command, args.uid, args.mount_dir)?;
        Ok(Container { config })
    }

    pub fn create(&mut self) -> Result<(), Error> {
        log::debug!("Creation finished");
        Ok(())
    }

    pub fn clean_exit(&mut self) -> Result<(), Error> {
        log::debug!("Cleaning container");
        Ok(())
    }
}

pub const MINIMAL_KERNEL_VERSION: f32 = 4.8;
pub const SUPPORTED_ARCH: &str = "x86_64";

pub fn check_linux_version() -> Result<(), Error> {
    let host = uname().map_err(Error::SystemInfoError)?;
    log::debug!("Linux release: {:?}", host.release());

    let version = scan_fmt!(
        host.release()
            .to_str()
            .expect("System version should be a valid UTF-8 string"),
        "{f}.{}",
        f32
    )
    .map_err(Error::SystemInfoScanError)?;

    if version < MINIMAL_KERNEL_VERSION {
        return Err(Error::UnsupportedKernelVersion);
    }

    if host.machine() != SUPPORTED_ARCH {
        return Err(Error::UnsupportedArchitecture);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn container_config_new() {
        assert!(ContainerConfig::new("command".to_string(), 0, "/mount".into()).is_ok());
        assert_eq!(
            ContainerConfig::new("".to_string(), 0, "/mount".into())
                .err()
                .unwrap(),
            Error::NoBinayPath
        );
    }
}
