use super::{raw_file::FileStream, JournalFlag};
use crate::pfs::sys::error::{FsError, FsResult};
use core::ffi::CStr;
use std::path::Path;

// 4MB
const DEFAULT_BUF_SIZE: usize = 4 * 1024 * 1024;
pub struct Journal {
    buf: Vec<u8>,
    raw_file: FileStream,
    append_pos: u64,
}

impl Journal {
    pub fn open(name: &Path) -> FsResult<Journal> {
        let mode = CStr::from_bytes_with_nul(b"wb\0")
            .map_err(|_| libc::EINVAL)
            .map_err(|e| FsError::OsError(e))?;
        let raw_file = FileStream::open(name, &mode).map_err(|e| FsError::OsError(e))?;
        let buf = vec![0; DEFAULT_BUF_SIZE];
        Ok(Journal {
            raw_file,
            buf,
            append_pos: 0,
        })
    }

    pub fn append(&mut self, data: &[u8]) -> FsResult {
        let n = data.len();
        self.buf[self.append_pos as usize] = JournalFlag::Node as u8;
        self.append_pos += 1;
        self.buf[self.append_pos as usize..self.append_pos as usize + n].copy_from_slice(data);
        self.append_pos += n as u64;
        Ok(())
    }

    pub fn flush(&mut self) -> FsResult {
        // raw_file is in append mode, write into it directly
        self.raw_file
            .write(&self.buf)
            .map_err(|e| FsError::OsError(e))?;

        self.raw_file.flush().map_err(|e| FsError::OsError(e))
    }
}
