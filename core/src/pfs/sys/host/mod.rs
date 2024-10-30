use std::path::Path;

use crate::pfs::sys::error::FsResult;

pub trait HostFs {
    fn read(&mut self, number: u64, node: &mut dyn AsMut<[u8]>) -> FsResult;
    fn write(&mut self, number: u64, node: &dyn AsRef<[u8]>) -> FsResult;
    fn flush(&mut self) -> FsResult;
}

#[derive(Debug)]
pub struct HostFile {}

impl HostFile {
    pub fn open(path: &Path, readonly: bool) -> FsResult<Self> {
        todo!()
    }

    pub fn size(&self) -> u64 {
        todo!()
    }
}

impl HostFs for HostFile {
    fn read(&mut self, number: u64, node: &mut dyn AsMut<[u8]>) -> FsResult {
        todo!()
    }

    fn write(&mut self, number: u64, node: &dyn AsRef<[u8]>) -> FsResult {
        todo!()
    }

    fn flush(&mut self) -> FsResult {
        todo!()
    }
}

pub fn recovery(path: &Path, recovery_path: &Path) -> FsResult {
    todo!()
}

pub fn try_exists(path: &Path) -> FsResult<bool> {
    todo!()
}

pub fn remove(path: &Path) -> FsResult {
    todo!()
}

#[derive(Debug)]
pub struct RecoveryFile {}

impl RecoveryFile {
    pub fn open(path: &Path) -> FsResult<Self> {
        todo!()
    }
}
impl HostFs for RecoveryFile {
    fn read(&mut self, number: u64, node: &mut dyn AsMut<[u8]>) -> FsResult {
        todo!()
    }

    fn write(&mut self, number: u64, node: &dyn AsRef<[u8]>) -> FsResult {
        todo!()
    }

    fn flush(&mut self) -> FsResult {
        todo!()
    }
}
