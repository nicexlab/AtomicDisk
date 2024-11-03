use crate::ensure;
use crate::pfs::sys::error::{FsError, FsResult, OsResult, ENOTSUP};
use crate::pfs::sys::host::RECOVERY_NODE_SIZE;
use crate::pfs::sys::node::NODE_SIZE;
use crate::{bail, eos};
use hashbrown::HashSet;
use libc::c_void;
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Error, ErrorKind, SeekFrom};
use std::mem::{self, ManuallyDrop};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::path::Path;

use super::{HostFs, JournalFlag, MAX_FOPEN_RETRIES, MILISECONDS_SLEEP_FOPEN};
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

    pub fn commit(&mut self) -> FsResult {
        self.file
            .write(&[JournalFlag::Commit as u8])
            .map_err(|e| eos!(e))
    }
}

impl HostFs for RecoveryFile {
    fn read(&mut self, _number: u64, _node: &mut dyn AsMut<[u8]>) -> FsResult {
        bail!(eos!(ENOTSUP))
    }

    fn write(&mut self, _number: u64, node: &dyn AsRef<[u8]>) -> FsResult {
        let mut node_buf = vec![0u8; RECOVERY_NODE_SIZE + 1];
        node_buf[0] = JournalFlag::Node as u8;
        node_buf[1..].copy_from_slice(node.as_ref());
        self.file.write(&node_buf).map_err(|e| eos!(e))
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
        let is_valid_length = node.len() == RECOVERY_NODE_SIZE + 1 || node.len() == 1;
        ensure!(is_valid_length, libc::EINVAL);

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

    let mut offset = 0;
    let mut flag_buf = vec![0_u8; 1];
    let mut last_commit_offset = offset;
    while offset <= size {
        recov
            .seek(SeekFrom::Start(offset as u64))
            .map_err(|e| FsError::OsError(e))?;
        recov
            .read(flag_buf.as_mut_slice())
            .map_err(|e| FsError::OsError(e))?;
        let flag: JournalFlag = flag_buf[0].into();
        offset += 1;

        match flag {
            JournalFlag::Node => {
                // just find the last commit offset, skip the node
                offset += RECOVERY_NODE_SIZE;
            }
            JournalFlag::Commit => {
                last_commit_offset = offset;
            }
        }
    }

    //  ensure!(size % RECOVERY_NODE_SIZE == 0, eos!(ENOTSUP));

    let mode = CStr::from_bytes_with_nul(b"r+b\0")
        .map_err(|_| libc::EINVAL)
        .map_err(|e| FsError::OsError(e))?;
    let src = FileStream::open(source, mode).map_err(|e| FsError::OsError(e))?;

    offset = 0;

    let mut data_buf = vec![0_u8; RECOVERY_NODE_SIZE];

    let mut set = HashSet::new();
    while offset <= size {
        recov
            .seek(SeekFrom::Start(offset as u64))
            .map_err(|e| FsError::OsError(e))?;
        recov
            .read(flag_buf.as_mut_slice())
            .map_err(|e| FsError::OsError(e))?;
        offset += 1;
        let flag: JournalFlag = flag_buf[0].into();

        match flag {
            JournalFlag::Node => {
                recov
                    .seek(SeekFrom::Start(offset as u64))
                    .map_err(|e| FsError::OsError(e))?;
                recov
                    .read(data_buf.as_mut_slice())
                    .map_err(|e| FsError::OsError(e))?;

                //let physical_node_number = u64::from_ne_bytes(data_buf[0..8].try_into().unwrap());
                let mut number = [0u8; 8];
                number.copy_from_slice(&data_buf[0..8]);
                let physical_node_number = u64::from_ne_bytes(number);

                if offset >= last_commit_offset {
                    // the node is already committed, the updated node is uncommitted,skip it
                    if set.contains(&physical_node_number) {
                        continue;
                    }
                    set.insert(physical_node_number);
                }
                offset += RECOVERY_NODE_SIZE;
                src.seek(SeekFrom::Start(physical_node_number * NODE_SIZE as u64))
                    .map_err(|e| FsError::OsError(e))?;
                src.write(&data_buf[8..]).map_err(|e| FsError::OsError(e))?;
            }
            JournalFlag::Commit => {}
        }
    }

    src.flush().map_err(|e| FsError::OsError(e))?;
    remove(recovery)
}

mod tests {
    use std::path::Path;

    use crate::pfs::sys::{
        host::{HostFile, HostFs, RECOVERY_NODE_SIZE},
        node::NODE_SIZE,
    };

    use super::{recovery, RawRecoveryFile, RecoveryFile};

    #[test]
    fn test_recovery() {
        let source_path = Path::new("test_source");
        let recovery_path = Path::new("test_recovery");
        let _ = HostFile::open(source_path, false).unwrap();
        let mut recover_file = RecoveryFile::open(recovery_path).unwrap();
        for i in 0..4 {
            let mut buf = vec![i as u8; RECOVERY_NODE_SIZE];
            buf.as_mut_slice()[0..8].copy_from_slice(&(i as u64).to_ne_bytes());
            recover_file.write(i as u64, &buf).unwrap();
        }
        recover_file.commit().unwrap();

        for i in 4..8 {
            let mut buf = vec![i as u8; RECOVERY_NODE_SIZE];
            buf.as_mut_slice()[0..8].copy_from_slice(&(i as u64).to_ne_bytes());
            recover_file.write(i as u64, &buf).unwrap();
        }
        recovery(source_path, recovery_path).unwrap();

        let mut source_file = HostFile::open(source_path, false).unwrap();
        for i in 0..4 {
            let mut buf = vec![0u8; NODE_SIZE];
            let expected = vec![i as u8; NODE_SIZE];
            source_file.read(i as u64, &mut buf).unwrap();
            assert_eq!(buf, expected);
        }
    }
}
