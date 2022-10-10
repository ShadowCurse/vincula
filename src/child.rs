use std::{
    fs::{create_dir_all, remove_dir},
    os::unix::prelude::RawFd,
    path::PathBuf,
};

use nix::{
    errno::Errno,
    mount::{mount, umount2, MntFlags, MsFlags},
    sched::{clone, CloneFlags},
    sys::signal::Signal,
    unistd::{chdir, pivot_root, sethostname, Pid},
};

use crate::{container::ContainerConfig, utils::random_string};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error while setting hostname: {0}")]
    SetHostname(Errno),
    #[error("Error while mounting directory: {0}")]
    Mount(Errno),
    #[error("Error while executing pivot root: {0}")]
    PivotRoot(Errno),
    #[error("Error while changing directory: {0}")]
    ChDir(Errno),
    #[error("Error while changing directory: {0}")]
    Umount(Errno),
    #[error("Error while creating directory: {0}")]
    CreateDir(std::io::Error),
    #[error("Error while changing directory: {0}")]
    RemoveDir(std::io::Error),
}

#[allow(clippy::from_over_into)]
impl Into<isize> for Error {
    fn into(self) -> isize {
        match self {
            Error::SetHostname(_) => -1,
            Error::Mount(_) => -2,
            Error::PivotRoot(_) => -3,
            Error::ChDir(_) => -4,
            Error::Umount(_) => -5,
            Error::CreateDir(_) => -6,
            Error::RemoveDir(_) => -7,
        }
    }
}

pub struct Child;

impl Child {
    const STACK_SIZE: usize = 1024 * 1024;

    /// Creates new child process by cloning current one and returns new PID
    /// Child process starts executing ['Child::run'] method
    #[allow(clippy::new_ret_no_self)]
    pub fn new(config: &ContainerConfig, socket: RawFd) -> Result<Pid, Errno> {
        log::debug!("Creating child process");
        let mut stack = [0u8; Self::STACK_SIZE];
        let flags = CloneFlags::from_bits_truncate(
            CloneFlags::CLONE_NEWNS.bits()
                | CloneFlags::CLONE_NEWCGROUP.bits()
                | CloneFlags::CLONE_NEWPID.bits()
                | CloneFlags::CLONE_NEWIPC.bits()
                | CloneFlags::CLONE_NEWNET.bits()
                | CloneFlags::CLONE_NEWUTS.bits(),
        );

        clone(
            Box::new(|| Self::run(config.clone(), socket)),
            &mut stack,
            flags,
            Some(Signal::SIGCHLD as i32),
        )
    }

    fn run(config: ContainerConfig, socket: RawFd) -> isize {
        log::debug!(
            "Executing: {:?} with args: {:?}",
            config.binary_path,
            config.argv
        );

        match Self::run_inner(config, socket) {
            Ok(_) => 0,
            Err(e) => {
                log::error!("Error in child process: {}", e);
                e.into()
            }
        }
    }

    fn run_inner(config: ContainerConfig, _socket: RawFd) -> Result<(), Error> {
        sethostname(config.hostname.clone()).map_err(Error::SetHostname)?;
        Self::change_root(&config)?;
        Ok(())
    }

    fn change_root(config: &ContainerConfig) -> Result<(), Error> {
        // Remounting root
        let mount_flags =
            MsFlags::from_bits_truncate(MsFlags::MS_REC.bits() | MsFlags::MS_PRIVATE.bits());
        mount(
            Option::<&PathBuf>::None,
            &PathBuf::from("/"),
            Option::<&PathBuf>::None,
            mount_flags,
            Option::<&PathBuf>::None,
        )
        .map_err(Error::Mount)?;

        // Creating new root
        let new_root = PathBuf::from(format!(
            "/tmp/vincula.{}.{}",
            config.hostname,
            random_string(16)
        ));
        create_dir_all(new_root.clone()).map_err(Error::CreateDir)?;

        // Mounting provided path to new root
        let mount_flags =
            MsFlags::from_bits_truncate(MsFlags::MS_BIND.bits() | MsFlags::MS_PRIVATE.bits());
        mount(
            Some(&config.mount_dir),
            &new_root,
            Option::<&PathBuf>::None,
            mount_flags,
            Option::<&PathBuf>::None,
        )
        .map_err(Error::Mount)?;

        // Creating directory for the old root
        let old_root = PathBuf::from(format!("old_root.{}", random_string(16)));
        let old_root_dir = new_root.join(old_root.clone());
        create_dir_all(old_root_dir.clone()).map_err(Error::CreateDir)?;

        // Pivot the root
        pivot_root(&new_root, &old_root_dir).map_err(Error::PivotRoot)?;

        // Changing to root
        chdir(&PathBuf::from("/")).map_err(Error::ChDir)?;

        // Unmounting old root
        umount2(&old_root, MntFlags::MNT_DETACH).map_err(Error::Umount)?;

        // Removing old root directory
        remove_dir(&old_root).map_err(Error::RemoveDir)?;
        Ok(())
    }
}
