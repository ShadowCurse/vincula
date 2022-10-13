use std::{
    fs::{create_dir_all, remove_dir},
    os::unix::prelude::RawFd,
    path::PathBuf,
};

use nix::{
    errno::Errno,
    mount::{mount, umount2, MntFlags, MsFlags},
    sched::{clone, unshare, CloneFlags},
    sys::signal::Signal,
    unistd::{chdir, pivot_root, setgroups, sethostname, setresgid, setresuid, Gid, Pid, Uid},
};

use crate::{
    container::ContainerConfig,
    sockets::{self, SocketReceive, SocketSend},
    utils::random_string,
};

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
    #[error("Error in socket: {0}")]
    SocketError(sockets::Error),
    #[error("Error while setting UID/GID")]
    AbortSetUid,
    #[error("Error while setting groups: {0}")]
    SetGroups(Errno),
    #[error("Error while setting resgid: {0}")]
    SetResgid(Errno),
    #[error("Error while setting resuid: {0}")]
    SetResuid(Errno),
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
            Error::SocketError(_) => -8,
            Error::AbortSetUid => -9,
            Error::SetGroups(_) => -10,
            Error::SetResgid(_) => -11,
            Error::SetResuid(_) => -12,
        }
    }
}

pub struct Child;

impl Child {
    pub const STACK_SIZE: usize = 1024 * 1024;
    pub const TMP_ROOT_PATH_SIZE: usize = "/tmp/vincula.".len() + 16;

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

    fn run_inner(config: ContainerConfig, socket: RawFd) -> Result<(), Error> {
        sethostname(config.hostname.clone()).map_err(Error::SetHostname)?;
        Self::change_root(&config, socket)?;
        Self::set_uid(config.uid, socket)?;
        Ok(())
    }

    fn change_root(config: &ContainerConfig, socket: RawFd) -> Result<(), Error> {
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
        let new_root = format!("/tmp/vincula.{}", random_string(16));
        let new_root_path = PathBuf::from(new_root.clone());
        create_dir_all(new_root_path.clone()).map_err(Error::CreateDir)?;

        // Mounting provided path to new root
        let mount_flags =
            MsFlags::from_bits_truncate(MsFlags::MS_BIND.bits() | MsFlags::MS_PRIVATE.bits());
        mount(
            Some(&config.mount_dir),
            &new_root_path,
            Option::<&PathBuf>::None,
            mount_flags,
            Option::<&PathBuf>::None,
        )
        .map_err(Error::Mount)?;

        // Creating directory for the old root
        let old_root = PathBuf::from(format!("old_root.{}", random_string(16)));
        let old_root_dir = new_root_path.join(old_root.clone());
        create_dir_all(old_root_dir.clone()).map_err(Error::CreateDir)?;

        // Pivot the root
        pivot_root(&new_root_path, &old_root_dir).map_err(Error::PivotRoot)?;

        // Changing to root
        chdir(&PathBuf::from("/")).map_err(Error::ChDir)?;

        // Unmounting old root
        umount2(&old_root, MntFlags::MNT_DETACH).map_err(Error::Umount)?;

        // Removing old root directory
        remove_dir(&old_root).map_err(Error::RemoveDir)?;

        // Sending root path to parent so it would clean this directory in cleanup
        <RawFd as SocketSend<[u8; Self::TMP_ROOT_PATH_SIZE]>>::send(
            &socket,
            new_root.into_bytes().try_into().unwrap(),
        )
        .map_err(Error::SocketError)?;

        Ok(())
    }

    fn set_uid(uid: u32, socket: RawFd) -> Result<(), Error> {
        let has_userns = unshare(CloneFlags::CLONE_NEWUSER).is_ok();
        log::debug!("Checking userns support: {}", has_userns);

        // Notifing parent of userns support
        socket.send(has_userns).map_err(Error::SocketError)?;

        // Waiting for parent responce
        let abort = socket.receive().map_err(Error::SocketError)?;
        if abort {
            return Err(Error::AbortSetUid);
        }

        log::debug!("Setting UID and GID to {}", uid);
        let gid = Gid::from_raw(uid);
        let uid = Uid::from_raw(uid);
        setgroups(&[gid]).map_err(Error::SetGroups)?;
        setresgid(gid, gid, gid).map_err(Error::SetResgid)?;
        setresuid(uid, uid, uid).map_err(Error::SetResuid)?;

        Ok(())
    }
}
