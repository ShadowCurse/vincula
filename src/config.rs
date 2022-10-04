use std::ffi::CString;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    #[error("No binary path provided in the commands")]
    NoBinayPath,
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
