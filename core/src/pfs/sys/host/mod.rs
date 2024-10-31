use libc::c_void;
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Error, ErrorKind, SeekFrom};
use std::mem::{self, ManuallyDrop};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::path::Path;

use crate::ensure;
use crate::pfs::sys::error::ENOTSUP;
use crate::{bail, eos};

use super::error::{FsError, FsResult, OsResult};

const MILISECONDS_SLEEP_FOPEN: u32 = 10;
const MAX_FOPEN_RETRIES: usize = 10;
const NODE_SIZE: usize = 4096;
const RECOVERY_NODE_SIZE: usize = mem::size_of::<u64>() + NODE_SIZE;

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

#[derive(Debug)]
pub struct RawFile {
    stream: FileStream,
    fd: RawFd,
}

impl RawFile {
    pub fn open(name: &Path, readonly: bool) -> OsResult<RawFile> {
        let mut open_mode = OpenOptions::new();
        open_mode.read(true);
        if !readonly {
            open_mode.write(true).create(true);
        }

        let oflag = libc::O_LARGEFILE;
        let mode = libc::S_IRUSR
            | libc::S_IWUSR
            | libc::S_IRGRP
            | libc::S_IWGRP
            | libc::S_IROTH
            | libc::S_IWOTH;

        let file = open_mode
            .mode(mode)
            .custom_flags(oflag)
            .open(name)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        // this lock is advisory only and programs with high priviliges can ignore it
        // it is set to help the user avoid mistakes, but it won't prevent intensional DOS attack from priviliged user
        let op = if readonly {
            libc::LOCK_SH
        } else {
            libc::LOCK_EX
        } | libc::LOCK_NB; // NB - non blocking

        let fd = file.as_raw_fd();
        unsafe {
            if libc::flock(fd, op) < 0 {
                Err(errno())
            } else {
                Ok(())
            }
        }?;

        let mode = CStr::from_bytes_with_nul(if readonly { b"rb\0" } else { b"r+b\0" })
            .map_err(|_| libc::EINVAL)?;
        let stream = unsafe {
            FileStream::from_raw_fd(fd, mode).map_err(|e| {
                libc::flock(fd, libc::LOCK_UN);
                e
            })
        }?;

        Ok(RawFile {
            stream,
            fd: file.into_raw_fd(),
        })
    }

    pub fn read(&mut self, number: u64, node: &mut [u8]) -> OsResult {
        ensure!(node.len() == NODE_SIZE, libc::EINVAL);

        let offset = number * NODE_SIZE as u64;
        self.stream.seek(SeekFrom::Start(offset))?;
        self.stream.read(node)
    }

    pub fn write(&mut self, number: u64, node: &[u8]) -> OsResult {
        ensure!(node.len() == NODE_SIZE, libc::EINVAL);

        let offset = number * NODE_SIZE as u64;
        self.stream.seek(SeekFrom::Start(offset))?;
        self.stream.write(node)
    }

    pub fn flush(&mut self) -> OsResult {
        self.stream.flush()
    }

    pub fn size(&self) -> OsResult<usize> {
        let file = ManuallyDrop::new(unsafe { File::from_raw_fd(self.fd) });
        let metadata = file
            .metadata()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        ensure!(metadata.is_file(), libc::EINVAL);
        Ok(metadata.len() as usize)
    }

    pub fn into_raw_stream(self) -> RawFileStream {
        ManuallyDrop::new(self).stream.stream
    }

    /// # Safety
    pub unsafe fn from_raw_stream(stream: RawFileStream) -> OsResult<RawFile> {
        ensure!(!stream.is_null(), libc::EINVAL);
        let fd = libc::fileno(stream);
        ensure!(fd >= 0, errno());

        Ok(Self {
            stream: FileStream { stream },
            fd,
        })
    }
}

impl Drop for RawFile {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.fd, libc::LOCK_UN);
        }
    }
}

#[derive(Debug)]
pub struct RecoveryFile {
    file: RawRecoveryFile,
}

impl RecoveryFile {
    pub fn open(name: &Path) -> FsResult<RecoveryFile> {
        let file = RawRecoveryFile::open(name).map_err(|e| FsError::OsError(e))?;
        Ok(RecoveryFile { file })
    }
}

impl HostFs for RecoveryFile {
    fn read(&mut self, _number: u64, _node: &mut dyn AsMut<[u8]>) -> FsResult {
        bail!(eos!(ENOTSUP))
    }

    fn write(&mut self, _number: u64, node: &dyn AsRef<[u8]>) -> FsResult {
        self.file.write(node.as_ref()).map_err(|e| eos!(e))
    }

    fn flush(&mut self) -> FsResult {
        bail!(eos!(ENOTSUP))
    }
}

#[derive(Debug)]
pub struct RawRecoveryFile {
    stream: FileStream,
}

impl RawRecoveryFile {
    pub fn open(name: &Path) -> OsResult<RawRecoveryFile> {
        let mode = CStr::from_bytes_with_nul(b"wb\0").map_err(|_| libc::EINVAL)?;
        for _ in 0..MAX_FOPEN_RETRIES {
            if let Ok(stream) = FileStream::open(name, mode) {
                return Ok(RawRecoveryFile { stream });
            }
            unsafe { libc::usleep(MILISECONDS_SLEEP_FOPEN) };
        }
        Err(libc::EBUSY)
    }

    pub fn write(&mut self, node: &[u8]) -> OsResult {
        ensure!(node.len() == RECOVERY_NODE_SIZE, libc::EINVAL);

        self.stream.write(node)
    }

    pub fn into_raw_stream(self) -> RawFileStream {
        ManuallyDrop::new(self).stream.stream
    }

    /// # Safety
    pub unsafe fn from_raw_stream(stream: RawFileStream) -> OsResult<RawRecoveryFile> {
        Ok(Self {
            stream: FileStream { stream },
        })
    }
}

pub type RawFileStream = *mut libc::FILE;

fn cstr(name: &Path) -> OsResult<CString> {
    CString::new(name.to_str().ok_or(libc::EINVAL)?).map_err(|_| libc::EINVAL)
}

fn errno() -> i32 {
    Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[derive(Debug)]
struct FileStream {
    stream: RawFileStream,
}

impl FileStream {
    fn open(name: &Path, mode: &CStr) -> OsResult<FileStream> {
        let name = cstr(name)?;
        let stream = unsafe { libc::fopen(name.as_ptr(), mode.as_ptr()) };
        if stream.is_null() {
            Err(errno())
        } else {
            Ok(FileStream { stream })
        }
    }

    fn read(&self, buf: &mut [u8]) -> OsResult {
        let size =
            unsafe { libc::fread(buf.as_mut_ptr() as *mut c_void, buf.len(), 1, self.stream) };
        if size != 1 {
            let err = self.last_error();
            if err != 0 {
                bail!(err);
            } else if errno() != 0 {
                bail!(errno());
            } else {
                bail!(libc::EIO);
            }
        }
        Ok(())
    }

    fn write(&self, buf: &[u8]) -> OsResult {
        let size =
            unsafe { libc::fwrite(buf.as_ptr() as *const c_void, 1, buf.len(), self.stream) };
        if size != buf.len() {
            let err = self.last_error();
            if err != 0 {
                bail!(err);
            } else if errno() != 0 {
                bail!(errno());
            } else {
                bail!(libc::EIO);
            }
        }
        Ok(())
    }

    fn flush(&self) -> OsResult {
        if unsafe { libc::fflush(self.stream) } != 0 {
            bail!(errno())
        }
        Ok(())
    }

    fn seek(&self, pos: SeekFrom) -> OsResult {
        let (offset, whence) = match pos {
            SeekFrom::Start(off) => (off as i64, libc::SEEK_SET),
            SeekFrom::End(off) => (off, libc::SEEK_END),
            SeekFrom::Current(off) => (off, libc::SEEK_CUR),
        };
        if unsafe { libc::fseeko(self.stream, offset, whence) } != 0 {
            bail!(errno())
        }
        Ok(())
    }

    fn tell(&self) -> OsResult<u64> {
        let off = unsafe { libc::ftello(self.stream) };
        ensure!(off >= 0, errno());

        Ok(off as u64)
    }

    fn last_error(&self) -> i32 {
        unsafe { libc::ferror(self.stream) }
    }

    /// # Safety
    unsafe fn from_raw_fd(fd: RawFd, mode: &CStr) -> OsResult<FileStream> {
        let stream = libc::fdopen(fd, mode.as_ptr());
        ensure!(!stream.is_null(), errno());

        Ok(FileStream { stream })
    }
}

impl Drop for FileStream {
    fn drop(&mut self) {
        let _ = unsafe { libc::fclose(self.stream) };
    }
}

pub fn remove(name: &Path) -> FsResult {
    fs::remove_file(name).map_err(|e| FsError::OsError(e.raw_os_error().unwrap_or(libc::EIO)))
}

pub fn try_exists(path: &Path) -> FsResult<bool> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(FsError::OsError(error.raw_os_error().unwrap_or(libc::EIO))),
    }
}

pub fn recovery(source: &Path, recovery: &Path) -> FsResult {
    let mode = CStr::from_bytes_with_nul(b"rb\0")
        .map_err(|_| libc::EINVAL)
        .map_err(|e| FsError::OsError(e))?;
    let recov = FileStream::open(recovery, mode).map_err(|e| FsError::OsError(e))?;

    recov
        .seek(SeekFrom::End(0))
        .map_err(|e| FsError::OsError(e))?;
    let size = recov.tell().map_err(|e| FsError::OsError(e))? as usize;
    recov
        .seek(SeekFrom::Start(0))
        .map_err(|e| FsError::OsError(e))?;

    ensure!(size % RECOVERY_NODE_SIZE == 0, eos!(ENOTSUP));

    let nodes_count = size / RECOVERY_NODE_SIZE;

    let mode = CStr::from_bytes_with_nul(b"r+b\0")
        .map_err(|_| libc::EINVAL)
        .map_err(|e| FsError::OsError(e))?;
    let src = FileStream::open(source, mode).map_err(|e| FsError::OsError(e))?;

    let mut data = vec![0_u8; RECOVERY_NODE_SIZE];
    for _ in 0..nodes_count {
        recov
            .read(data.as_mut_slice())
            .map_err(|e| FsError::OsError(e))?;
        // seek the regular file to the required offset
        let mut number = [0u8; 8];
        number.copy_from_slice(&data[0..8]);
        let physical_node_number = u64::from_ne_bytes(number);

        src.seek(SeekFrom::Start(physical_node_number * NODE_SIZE as u64))
            .map_err(|e| FsError::OsError(e))?;
        src.write(&data[8..]).map_err(|e| FsError::OsError(e))?;
    }

    src.flush().map_err(|e| FsError::OsError(e))?;
    remove(recovery)
}
