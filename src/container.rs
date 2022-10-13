use std::ffi::CString;
use std::fs::{remove_dir, File};
use std::io::Write;
use std::os::unix::prelude::RawFd;
use std::path::PathBuf;
use std::string::FromUtf8Error;

use nix::errno::Errno;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use scan_fmt::parse::ScanError;

use crate::args::Args;
use crate::child::Child;
use crate::sockets::{self, close_socket, create_socketpair, SocketReceive, SocketSend};
use crate::utils::{gid_file, uid_file};

#[derive(Debug, thiserror::Error)]
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
    #[error("Error in socket: {0}")]
    Socket(sockets::Error),
    #[error("Error while creating child process: {0}")]
    CreateChild(Errno),
    #[error("Error while receiving child root directory: {0}")]
    InvalidChildRootDir(FromUtf8Error),
    #[error("Error while whaiting for child to finish: {0}")]
    WaitPid(Errno),
    #[error("Error while dealing with uid map file: {0}")]
    UidMap(std::io::Error),
    #[error("Error while dealing with gid map file: {0}")]
    GidMap(std::io::Error),
    #[error("Error while removing child root directory: {0}")]
    ChildRootDir(std::io::Error),
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
    child_root_dir: Option<String>,
}

impl Container {
    const USERNS_OFFSET: u32 = 10000;
    const USERNS_COUNT: u32 = 200;

    pub fn new(args: Args) -> Result<Container, Error> {
        let config = ContainerConfig::new(args.command, args.uid, args.mount_dir, args.hostname)?;
        let sockets = create_socketpair().map_err(Error::Socket)?;
        Ok(Container {
            config,
            sockets,
            child_pid: None,
            child_root_dir: None,
        })
    }

    pub fn create(&mut self) -> Result<(), Error> {
        log::info!("Creating container");
        self.child_pid =
            Some(Child::new(&self.config, self.sockets.0).map_err(Error::CreateChild)?);
        self.get_child_root_dir()?;
        self.handle_child_uid_map()?;
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
        close_socket(self.sockets.0).map_err(Error::Socket)?;
        close_socket(self.sockets.1).map_err(Error::Socket)?;
        remove_dir(self.child_root_dir.as_ref().unwrap()).map_err(Error::ChildRootDir)?;
        Ok(())
    }

    fn get_child_root_dir(&mut self) -> Result<(), Error> {
        let root_dir: [u8; Child::TMP_ROOT_PATH_SIZE] =
            self.sockets.1.receive().map_err(Error::Socket)?;
        let root_dir = String::from_utf8(root_dir.into()).map_err(Error::InvalidChildRootDir)?;
        log::debug!("Got child rood directory: {}", root_dir);
        self.child_root_dir = Some(root_dir);
        Ok(())
    }

    fn handle_child_uid_map(&self) -> Result<(), Error> {
        let has_userns = self.sockets.1.receive().map_err(Error::Socket)?;

        // Setting up userns for the child
        if has_userns {
            let content = format!("0 {} {}", Self::USERNS_OFFSET, Self::USERNS_COUNT);
            let mut uid_file =
                File::create(uid_file(self.child_pid.unwrap())).map_err(Error::UidMap)?;
            uid_file
                .write_all(content.as_bytes())
                .map_err(Error::UidMap)?;
            let mut gid_file =
                File::create(gid_file(self.child_pid.unwrap())).map_err(Error::GidMap)?;
            gid_file
                .write_all(content.as_bytes())
                .map_err(Error::GidMap)?;
        }

        self.sockets.1.send(false).map_err(Error::Socket)?;

        Ok(())
    }
}
