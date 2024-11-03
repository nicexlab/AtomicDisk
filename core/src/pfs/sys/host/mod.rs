use super::error::{FsError, FsResult, OsResult};
use super::node::NODE_SIZE;
use crate::ensure;
use crate::pfs::sys::error::ENOTSUP;
use crate::{bail, eos};
use libc::c_void;
use raw_file::RawFile;
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Error, ErrorKind, SeekFrom};
use std::mem::{self, ManuallyDrop};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::path::Path;

pub mod raw_file;

const MILISECONDS_SLEEP_FOPEN: u32 = 10;
const MAX_FOPEN_RETRIES: usize = 10;
const RECOVERY_NODE_SIZE: usize = mem::size_of::<u64>() + NODE_SIZE;

enum JournalFlag {
    Node,
    Commit,
}

impl From<JournalFlag> for u8 {
    fn from(flag: JournalFlag) -> Self {
        match flag {
            JournalFlag::Node => 0,
            JournalFlag::Commit => 1,
        }
    }
}

impl From<u8> for JournalFlag {
    fn from(flag: u8) -> Self {
        match flag {
            0 => JournalFlag::Node,
            1 => JournalFlag::Commit,
            _ => unreachable!("invalid journal flag, data corruption"),
        }
    }
}

pub trait HostFs {
    fn read(&mut self, number: u64, node: &mut dyn AsMut<[u8]>) -> FsResult;
    fn write(&mut self, number: u64, node: &dyn AsRef<[u8]>) -> FsResult;
    fn flush(&mut self) -> FsResult;
}

#[derive(Debug)]
pub struct HostFile {
    raw: RawFile,
}

impl HostFile {
    pub fn open(name: &Path, readonly: bool) -> FsResult<HostFile> {
        let raw = RawFile::open(name, readonly).map_err(|e| FsError::OsError(e))?;
        Ok(HostFile { raw })
    }

    pub fn size(&self) -> usize {
        self.raw.size().unwrap()
    }
}

impl HostFs for HostFile {
    fn read(&mut self, number: u64, node: &mut dyn AsMut<[u8]>) -> FsResult {
        self.raw
            .read(number, node.as_mut())
            .map_err(|err| FsError::OsError(err))
    }

    fn write(&mut self, number: u64, node: &dyn AsRef<[u8]>) -> FsResult {
        self.raw
            .write(number, node.as_ref())
            .map_err(|err| FsError::OsError(err))
    }

    fn flush(&mut self) -> FsResult {
        self.raw.flush().map_err(|err| FsError::OsError(err))
    }
}
