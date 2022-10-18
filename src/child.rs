use std::{
    ffi::CString,
    fs::{create_dir_all, remove_dir},
    os::unix::prelude::RawFd,
    path::PathBuf,
};

use capctl::{Cap, FullCapState};
use libc::{EPERM, TIOCSTI};
use nix::{
    errno::Errno,
    mount::{mount, umount2, MntFlags, MsFlags},
    sched::{clone, unshare, CloneFlags},
    sys::{signal::Signal, stat::Mode},
    unistd::{
        chdir, execve, pivot_root, setgroups, sethostname, setresgid, setresuid, Gid, Pid, Uid,
    },
};
use syscallz::{Action, Cmp, Comparator, Context, Syscall};

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
    #[error("Error while getting capabilities: {0}")]
    CapState(std::io::Error),
    #[error("Error while creating seccomp context: {0}")]
    SeccompCtx(syscallz::Error),
    #[error("Error while setting seccomp rule: {0}")]
    SeccompSetRule(syscallz::Error),
    #[error("Error while setting seccomp action: {0}")]
    SeccompSetAction(syscallz::Error),
    #[error("Error while loading seccomp: {0}")]
    SeccompLoad(syscallz::Error),
    #[error("Error while executing binary: {0}")]
    Execve(Errno),
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
            Error::CapState(_) => -13,
            Error::SeccompCtx(_) => -14,
            Error::SeccompSetRule(_) => -15,
            Error::SeccompSetAction(_) => -16,
            Error::SeccompLoad(_) => -17,
            Error::Execve(_) => -18,
        }
    }
}

pub struct Child;

impl Child {
    pub const STACK_SIZE: usize = 1024 * 1024;
    pub const TMP_ROOT_PATH_SIZE: usize = "/tmp/vincula.".len() + 16;
    pub const CAPABILITIES_DROP: [Cap; 21] = [
        Cap::AUDIT_CONTROL,
        Cap::AUDIT_READ,
        Cap::AUDIT_WRITE,
        Cap::BLOCK_SUSPEND,
        Cap::DAC_READ_SEARCH,
        Cap::DAC_OVERRIDE,
        Cap::FSETID,
        Cap::IPC_LOCK,
        Cap::MAC_ADMIN,
        Cap::MAC_OVERRIDE,
        Cap::MKNOD,
        Cap::SETFCAP,
        Cap::SYSLOG,
        Cap::SYS_ADMIN,
        Cap::SYS_BOOT,
        Cap::SYS_MODULE,
        Cap::SYS_NICE,
        Cap::SYS_RAWIO,
        Cap::SYS_RESOURCE,
        Cap::SYS_TIME,
        Cap::WAKE_ALARM,
    ];
    pub const SYSCALL_REFUSE_CMP: [(Syscall, u32, u64); 9] = [
        // Syscal | Arg position | Compare to
        (Syscall::chmod, 1, Mode::S_ISUID.bits() as u64),
        (Syscall::chmod, 1, Mode::S_ISGID.bits() as u64),
        (Syscall::fchmod, 1, Mode::S_ISUID.bits() as u64),
        (Syscall::fchmod, 1, Mode::S_ISGID.bits() as u64),
        (Syscall::fchmodat, 1, Mode::S_ISUID.bits() as u64),
        (Syscall::fchmodat, 1, Mode::S_ISUID.bits() as u64),
        (Syscall::unshare, 1, CloneFlags::CLONE_NEWUSER.bits() as u64),
        (Syscall::clone, 1, CloneFlags::CLONE_NEWUSER.bits() as u64),
        (Syscall::ioctl, 1, TIOCSTI),
    ];
    pub const SYSCALL_REFUSE: [Syscall; 9] = [
        Syscall::keyctl,
        Syscall::add_key,
        Syscall::request_key,
        Syscall::mbind,
        Syscall::migrate_pages,
        Syscall::move_pages,
        Syscall::set_mempolicy,
        Syscall::userfaultfd,
        Syscall::perf_event_open,
    ];

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

    /// Child execution starts here
    /// This method just wrapps ['Child::run_inner'] and converts its result into isize
    fn run(config: ContainerConfig, socket: RawFd) -> isize {
        match Self::run_inner(config, socket) {
            Ok(_) => 0,
            Err(e) => {
                log::error!("Error in child process: {}", e);
                e.into()
            }
        }
    }

    /// Main child runtime
    fn run_inner(config: ContainerConfig, socket: RawFd) -> Result<(), Error> {
        sethostname(config.hostname.clone()).map_err(Error::SetHostname)?;
        Self::set_mounts(&config, socket)?;
        Self::set_uid_gid(config.uid, socket)?;
        Self::set_capabilities()?;
        Self::restrict_syscalls()?;

        log::info!(
            "Executing: {:?} with args: {:?}",
            config.binary_path,
            config.argv
        );
        execve::<_, CString>(&config.binary_path, &config.argv, &[]).map_err(Error::Execve)?;

        Ok(())
    }

    /// This method deals with all mounting related stuff
    /// Overall steps are:
    /// - remount `/` with `MS_PRIVATE`
    /// - create new root directory in `/tmp` in a form `/tmp/vincula.{}`
    /// - mount provided path to new root
    /// - mount additional directories
    /// - create directory for the old root
    /// - `pivot_root` with new and old root
    /// - change directory to `/`
    /// - unmount old root
    /// - remove old root directory
    /// - send new root directory path to the parent process through the socket (for the cleanup)
    fn set_mounts(config: &ContainerConfig, socket: RawFd) -> Result<(), Error> {
        // Remounting old root
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

        // Mounting additional mounts
        for (from, to, args) in config.additional_mounts.iter() {
            // Creating directories for mounts
            let new_to = new_root_path.join(to);
            log::debug!("Mounting additional directory: {:?} to {:?}", from, new_to);
            create_dir_all(new_to.clone()).map_err(Error::CreateDir)?;

            let mut mount_flags =
                MsFlags::from_bits_truncate(MsFlags::MS_BIND.bits() | MsFlags::MS_PRIVATE.bits());
            if let Some(args) = args {
                mount_flags.insert(*args);
            }

            mount(
                Some(from),
                &new_to,
                Option::<&PathBuf>::None,
                mount_flags,
                Option::<&PathBuf>::None,
            )
            .map_err(Error::Mount)?;
        }

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
        socket
            .send(new_root.into_bytes().as_slice())
            .map_err(Error::SocketError)?;

        Ok(())
    }

    /// Sets uid and gid for the current process
    fn set_uid_gid(uid: u32, socket: RawFd) -> Result<(), Error> {
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

    /// Sets capabilities for the current process
    fn set_capabilities() -> Result<(), Error> {
        log::debug!("Clearing unwanted capabilities");
        let mut caps = FullCapState::get_current().map_err(Error::CapState)?;
        caps.bounding
            .drop_all(Self::CAPABILITIES_DROP.iter().cloned());
        caps.inheritable
            .drop_all(Self::CAPABILITIES_DROP.iter().cloned());
        Ok(())
    }

    /// Restricts syscalls for the current process
    fn restrict_syscalls() -> Result<(), Error> {
        log::debug!("Restricting syscalls");
        let mut ctx = Context::init_with_action(Action::Allow).map_err(Error::SeccompCtx)?;

        for (syscall, arg, cmp) in Self::SYSCALL_REFUSE_CMP.iter() {
            ctx.set_rule_for_syscall(
                Action::Errno(EPERM as u16),
                *syscall,
                &[Comparator::new(*arg, Cmp::MaskedEq, *cmp, Some(*cmp))],
            )
            .map_err(Error::SeccompSetRule)?;
        }

        for syscall in Self::SYSCALL_REFUSE.iter() {
            ctx.set_action_for_syscall(Action::Errno(EPERM as u16), *syscall)
                .map_err(Error::SeccompSetAction)?;
        }

        ctx.load().map_err(Error::SeccompLoad)?;

        Ok(())
    }
}
