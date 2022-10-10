use std::ffi::CString;
use std::os::unix::prelude::RawFd;
use std::path::PathBuf;

use nix::errno::Errno;
use nix::sys::wait::waitpid;
use nix::unistd::{close, Pid};
use scan_fmt::parse::ScanError;

use crate::args::Args;
use crate::child::Child;
use crate::sockets::create_socketpair;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    #[error("No binary path provided in the commands")]
    NoBinayPath,
    #[error("Unsupported kernel version")]
    UnsupportedKernelVersion,
    #[error("Unsupported architecture")]
    UnsupportedArchitecture,
    #[error("Error while getting system info: {0}")]
    SystemInfo(Errno),
    #[error("Error while scanning system info: {0}")]
    SystemInfoScan(ScanError),
    #[error("Error while creating socket pair: {0}")]
    SocketPairCreation(Errno),
    #[error("Error while closing socket: {0}")]
    SocketClose(Errno),
    #[error("Error while sending data into socket: {0}")]
    SocketSend(Errno),
    #[error("Error while receiving data from socket: {0}")]
    SocketReceive(Errno),
    #[error("Error while creating child process: {0}")]
    CreateChild(Errno),
    #[error("Error while whaiting for child to finish: {0}")]
    WaitPid(Errno),
}

#[derive(Debug, Clone)]
pub struct ContainerConfig {
    pub binary_path: CString,
    pub argv: Vec<CString>,

    pub uid: u32,
    pub mount_dir: PathBuf,
    pub hostname: String,
}

impl ContainerConfig {
    pub fn new(
        command: String,
        uid: u32,
        mount_dir: PathBuf,
        hostname: String,
    ) -> Result<Self, Error> {
        let argv = command
            .split_ascii_whitespace()
            .map(|s| CString::new(s).expect("Can not read arg"))
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
            hostname,
        })
    }
}

pub struct Container {
    config: ContainerConfig,
    // Child and parent sockets
    sockets: (RawFd, RawFd),
    child_pid: Option<Pid>,
}

impl Container {
    pub fn new(args: Args) -> Result<Container, Error> {
        let config = ContainerConfig::new(args.command, args.uid, args.mount_dir, args.hostname)?;
        let sockets = create_socketpair()?;
        Ok(Container {
            config,
            sockets,
            child_pid: None,
        })
    }

    pub fn create(&mut self) -> Result<(), Error> {
        log::info!("Creating container");
        self.child_pid =
            Some(Child::new(&self.config, self.sockets.0).map_err(Error::CreateChild)?);
        log::debug!("Creation finished");
        Ok(())
    }

    pub fn wait_for_child(&self) -> Result<(), Error> {
        if let Some(child_pid) = self.child_pid {
            log::debug!("Waiting for child to finish (pid: {})", child_pid);
            waitpid(child_pid, None).map_err(Error::WaitPid)?;
        }
        Ok(())
    }

    pub fn clean_exit(&mut self) -> Result<(), Error> {
        log::info!("Cleaning container");
        close(self.sockets.0).map_err(Error::SocketClose)?;
        close(self.sockets.1).map_err(Error::SocketClose)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn container_config_new() {
        assert!(ContainerConfig::new(
            "command".to_string(),
            0,
            "/mount".into(),
            "new_host".to_string()
        )
        .is_ok());
        assert_eq!(
            ContainerConfig::new("".to_string(), 0, "/mount".into(), "new_host".to_string())
                .err()
                .unwrap(),
            Error::NoBinayPath
        );
    }
}
