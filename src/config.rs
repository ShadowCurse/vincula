use std::ffi::CString;
use std::path::PathBuf;

#[derive(Clone)]
pub struct ContainerOpts {
    pub path: CString,
    pub argv: Vec<CString>,

    pub uid: u32,
    pub mount_dir: PathBuf,
}
