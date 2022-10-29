use std::ffi::CString;
use std::fs::{canonicalize, metadata, remove_dir, File};
use std::io::Write;
use std::os::unix::prelude::RawFd;
use std::path::PathBuf;
use std::string::FromUtf8Error;

use cgroups_rs::cgroup_builder::CgroupBuilder;
use cgroups_rs::hierarchies::V2;
use cgroups_rs::{CgroupPid, MaxValue};
use nix::errno::Errno;
use nix::mount::MsFlags;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use rlimit::{setrlimit, Resource};
use scan_fmt::parse::ScanError;

use crate::args::Args;
use crate::child::Child;
use crate::sockets::{self, close_socket, create_socketpair, SocketReceive, SocketSend};
use crate::utils::{gid_file, uid_file};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("No binary path provided in the commands")]
    NoBinayPath,
    #[error("Error in provided path: {0}")]
    PathError(std::io::Error),
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
    #[error("Error while adding task to cgroup: {0}")]
    CgroupAddTask(cgroups_rs::error::Error),
    #[error("Error while setting rlimit: {0}")]
    SetRlimit(std::io::Error),
    #[error("Error while cleaning cgroups: {0}")]
    CleanCgroups(std::io::Error),
    #[error("Error while getting canonical path: {0}")]
    NonCanonicalPath(std::io::Error),
    #[error("Error in parsing additional mount path: {0}")]
    AddionalMountPath(std::io::Error),
    #[error("Error in parsing additional mount arg")]
    AddionalMountArg,
}

#[derive(Debug, Clone)]
pub struct ContainerConfig {
    pub binary_path: CString,
    pub argv: Vec<CString>,

    pub uid: u32,
    pub mount_dir: PathBuf,
    pub additional_mounts: Vec<(PathBuf, PathBuf, Option<MsFlags>)>,
    pub hostname: String,
}

impl ContainerConfig {
    pub fn new(
        command: String,
        uid: u32,
        mount_dir: PathBuf,
        additional_mounts: Vec<String>,
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

        metadata(mount_dir.clone()).map_err(Error::PathError)?;

        let additional_mounts = additional_mounts
            .into_iter()
            .map(|mount| {
                let parts = mount.split(':').collect::<Vec<_>>();
                if parts.len() < 2 || parts.len() > 3 {
                    return Err(Error::AddionalMountArg);
                }
                let from = canonicalize(parts[0]).map_err(Error::AddionalMountPath)?;
                metadata(from.clone()).map_err(Error::PathError)?;
                let to = canonicalize(parts[1])
                    .map_err(Error::AddionalMountPath)?
                    .strip_prefix("/")
                    .expect("Target mount point should start with '/'")
                    .to_path_buf();
                let options = if parts.len() == 3 {
                    match parts[3] {
                        "R" => Some(MsFlags::MS_RDONLY),
                        _ => {
                            return Err(Error::AddionalMountArg);
                        }
                    }
                } else {
                    None
                };

                Ok((from, to, options))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            binary_path,
            argv,
            uid,
            mount_dir,
            additional_mounts,
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
    pub const USERNS_OFFSET: u32 = 10000;
    pub const USERNS_COUNT: u32 = 200;
    pub const KMEM_LIMIT: i64 = 1024 * 1024 * 1024;
    pub const MEM_LIMIT: i64 = Self::KMEM_LIMIT;
    pub const MAX_PID: MaxValue = MaxValue::Value(64);
    pub const NOFILE_RLIMTI: u64 = 64;

    pub fn new(args: Args) -> Result<Container, Error> {
        let config = ContainerConfig::new(
            args.command,
            args.uid,
            args.mount_dir,
            args.additional_mounts,
            args.hostname,
        )?;
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
        self.restrict_resources()?;
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

        log::debug!("Closing sockets");
        close_socket(self.sockets.0).map_err(Error::Socket)?;
        close_socket(self.sockets.1).map_err(Error::Socket)?;

        log::debug!("Removing child rood directory");
        remove_dir(self.child_root_dir.as_ref().unwrap()).map_err(Error::ChildRootDir)?;

        log::debug!("Removing additional mount points");
        for (_, to, _) in self.config.additional_mounts.iter() {
            remove_dir(self.config.mount_dir.join(to)).map_err(Error::AddionalMountPath)?;
        }

        log::debug!("Cleaning cgroups");
        self.clean_cgroups()?;

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

        log::debug!("Setting up userns for the child");
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

    fn restrict_resources(&self) -> Result<(), Error> {
        log::debug!("Restricting resources for the child");

        let cgs = CgroupBuilder::new(&self.config.hostname)
            .cpu()
            .shares(256)
            .done()
            .memory()
            .kernel_memory_limit(Self::KMEM_LIMIT)
            .memory_hard_limit(Self::MEM_LIMIT)
            .done()
            .pid()
            .maximum_number_of_processes(Self::MAX_PID)
            .done()
            .blkio()
            .weight(50)
            .done()
            .build(Box::new(V2::new()));

        cgs.add_task(CgroupPid::from(
            self.child_pid.as_ref().unwrap().as_raw() as u64
        ))
        .map_err(Error::CgroupAddTask)?;

        setrlimit(Resource::NOFILE, Self::NOFILE_RLIMTI, Self::NOFILE_RLIMTI)
            .map_err(Error::SetRlimit)?;

        Ok(())
    }

    fn clean_cgroups(&self) -> Result<(), Error> {
        let path = canonicalize(format!("/sys/fs/cgroup/{}/", self.config.hostname))
            .map_err(Error::NonCanonicalPath)?;
        remove_dir(path).map_err(Error::CleanCgroups)?;
        Ok(())
    }
}
