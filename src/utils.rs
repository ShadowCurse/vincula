use nix::{sys::utsname::uname, unistd::Pid};
use scan_fmt::scan_fmt;

use crate::container::Error;

pub fn setup_logging(debug: bool) {
    if debug {
        init_logging(log::LevelFilter::Debug);
    } else {
        init_logging(log::LevelFilter::Info);
    }
}

fn init_logging(level: log::LevelFilter) {
    env_logger::Builder::from_default_env()
        .format_timestamp_secs()
        .filter(None, level)
        .init();
}

/// Generates random string of requested size (max size is 62)
pub fn random_string(size: usize) -> String {
    use rand::seq::SliceRandom;

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";

    let mut rng = rand::thread_rng();

    CHARSET
        .choose_multiple(&mut rng, size)
        .map(|char| *char as char)
        .collect::<String>()
}

pub const MINIMAL_KERNEL_VERSION: f32 = 4.8;
pub const SUPPORTED_ARCH: &str = "x86_64";

/// Checks current linux version and system architecture
pub fn check_linux_version() -> Result<(), Error> {
    let host = uname().map_err(Error::SystemInfo)?;
    log::debug!("Linux release: {:?}", host.release());

    let version = scan_fmt!(
        host.release()
            .to_str()
            .expect("System version should be a valid UTF-8 string"),
        "{f}.{}",
        f32
    )
    .map_err(Error::SystemInfoScan)?;

    if version < MINIMAL_KERNEL_VERSION {
        return Err(Error::UnsupportedKernelVersion);
    }

    if host.machine() != SUPPORTED_ARCH {
        return Err(Error::UnsupportedArchitecture);
    }

    Ok(())
}

/// Generates path to uid file
pub fn uid_file(pid: Pid) -> String {
    format!("/proc/{}/{}", pid, "uid_map")
}

/// Generates path to gid file
pub fn gid_file(pid: Pid) -> String {
    format!("/proc/{}/{}", pid, "gid_map")
}
