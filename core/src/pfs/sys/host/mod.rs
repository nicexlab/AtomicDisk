use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::FileExt,
    path::Path,
};

use log::error;

use crate::{
    bail, eos,
    pfs::sys::error::{FsResult, ENOTSUP},
};

use super::error::{FsError, EINVAL, ENOENT};

pub trait HostFs {
    fn read(&mut self, number: u64, node: &mut dyn AsMut<[u8]>) -> FsResult;
    fn write(&mut self, number: u64, node: &dyn AsRef<[u8]>) -> FsResult;
    fn flush(&mut self) -> FsResult;
}

#[derive(Debug)]
pub struct HostFile {
    file: File,
}

impl HostFile {
    pub fn open(path: &Path, _readonly: bool) -> FsResult<Self> {
        let mut open_options = std::fs::OpenOptions::new();
        let file = open_options
            .create(true)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|err| {
                error!("open file failed: {:?}", err);
                FsError::OsError(err.raw_os_error().unwrap_or(ENOENT))
            })?;
        Ok(Self { file })
    }

    pub fn size(&self) -> u64 {
        self.file
            .metadata()
            .expect("failed to get file metadata")
            .len()
    }
}

impl HostFs for HostFile {
    fn read(&mut self, number: u64, node: &mut dyn AsMut<[u8]>) -> FsResult {
        self.file
            .read_at(node.as_mut(), number)
            .map_err(|err| FsError::OsError(err.raw_os_error().unwrap_or(EINVAL)))?;
        Ok(())
    }

    fn write(&mut self, number: u64, node: &dyn AsRef<[u8]>) -> FsResult {
        self.file
            .write_all_at(node.as_ref(), number)
            .map_err(|err| FsError::OsError(err.raw_os_error().unwrap_or(EINVAL)))?;
        Ok(())
    }

    fn flush(&mut self) -> FsResult {
        io::Write::flush(&mut self.file)
            .map_err(|err| FsError::OsError(err.raw_os_error().unwrap_or(EINVAL)))?;
        // self.file
        //     .sync_all()
        //     .map_err(|err| FsError::OsError(err.raw_os_error().unwrap_or(EINVAL)))?;
        Ok(())
    }
}

pub fn recovery(path: &Path, recovery_path: &Path) -> FsResult {
    todo!()
}

pub fn try_exists(path: &Path) -> FsResult<bool> {
    Ok(std::fs::metadata(path).is_ok())
}

pub fn remove(path: &Path) -> FsResult {
    std::fs::remove_file(path).map_err(|err| FsError::OsError(err.raw_os_error().unwrap_or(EINVAL)))
}

#[derive(Debug)]
pub struct RecoveryFile {
    file: File,
}

impl RecoveryFile {
    pub fn open(path: &Path) -> FsResult<Self> {
        let mut open_options = std::fs::OpenOptions::new();
        let file = open_options
            .create(true)
            .read(true)
            .append(true)
            .open(path)
            .map_err(|err| FsError::OsError(err.raw_os_error().unwrap_or(ENOENT)))?;
        Ok(Self { file })
    }
}
impl HostFs for RecoveryFile {
    fn read(&mut self, _number: u64, _node: &mut dyn AsMut<[u8]>) -> FsResult {
        bail!(eos!(ENOTSUP))
    }

    fn write(&mut self, number: u64, node: &dyn AsRef<[u8]>) -> FsResult {
        self.file
            .write_at(node.as_ref(), number)
            .map_err(|err| FsError::OsError(err.raw_os_error().unwrap_or(EINVAL)))?;
        Ok(())
    }

    fn flush(&mut self) -> FsResult {
        bail!(eos!(ENOTSUP))
    }
}

mod test {
    use super::*;

    #[test]
    fn simple_read_write() {
        let file_path = Path::new("test.data");
        let _ = std::fs::File::create(file_path).unwrap();

        let mut file = HostFile::open(file_path, false).unwrap();
        file.write(0, b"hello").unwrap();
        file.flush().unwrap();

        let mut read_buffer = vec![0u8; 5];
        file.read(0, &mut read_buffer).unwrap();
        assert_eq!(read_buffer, b"hello");
    }
}
