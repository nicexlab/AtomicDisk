// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

use crate::prelude::Result;
use crate::os::SeekFrom;
use crate::pfs::sys::file::{FileInner, FileStatus};
use crate::pfs::sys::host;
use crate::pfs::sys::metadata::FILENAME_MAX_LEN;
use crate::{bail, ensure, AeadMac, BlockSet, Errno};

use super::Error;

impl<D: BlockSet> FileInner<D> {
    #[inline]
    pub fn remove(_path: &str) -> Result<()> {
        unreachable!()
    }

    #[inline]
    pub fn tell(&mut self) -> Result<u64> {
        ensure!(self.status.is_ok(), Error::new(Errno::BadStatus));
        Ok(self.offset as u64)
    }

    #[inline]
    pub fn get_eof(&self) -> bool {
        self.end_of_file
    }

    #[inline]
    pub fn file_size(&self) -> Result<u64> {
        ensure!(self.status.is_ok(), Error::new(Errno::BadStatus));
        Ok(self.metadata.encrypted_plain.size as u64)
    }

    pub fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        ensure!(self.status.is_ok(), Error::new(Errno::BadStatus));

        let file_size = self.metadata.encrypted_plain.size as u64;
        let new_offset = match pos {
            SeekFrom::Start(off) => {
                if off <= file_size {
                    Some(off)
                } else {
                    None
                }
            }
            SeekFrom::End(off) => {
                if off <= 0 {
                    file_size.checked_sub((0 - off) as u64)
                } else {
                    None
                }
            }
            SeekFrom::Current(off) => {
                let cur_offset = self.offset as u64;
                if off >= 0 {
                    match cur_offset.checked_add(off as u64) {
                        Some(new_offset) if new_offset <= file_size => Some(new_offset),
                        _ => None,
                    }
                } else {
                    cur_offset.checked_sub((0 - off) as u64)
                }
            }
        }
        .ok_or(Error::new(Errno::InvalidArgs))
        .unwrap();

        self.offset = new_offset as usize;
        self.end_of_file = false;
        Ok(self.offset as u64)
    }

    pub fn set_len(&mut self, size: u64) -> Result<()> {
        let new_size = size as usize;
        let mut cur_offset = self.offset;
        let file_size = self.metadata.encrypted_plain.size;

        let mut reset_len = if new_size > file_size {
            // expand the file by padding null bytes
            self.seek(SeekFrom::End(0))?;
            new_size - file_size
        } else {
            // shrink the file by setting null bytes between len and file_size
            self.seek(SeekFrom::Start(size))?;
            file_size - new_size
        };

        static ZEROS: [u8; 0x1000] = [0; 0x1000];
        while reset_len > 0 {
            let len = reset_len.min(0x1000);

            let nwritten = match self.write(&ZEROS[..len]) {
                Ok(n) => n,
                Err(error) => {
                    if new_size > file_size {
                        self.offset = cur_offset;
                        bail!(error);
                    } else {
                        // ignore errors in shrinking files
                        break;
                    }
                }
            };
            reset_len -= nwritten;
        }

        if cur_offset > new_size {
            cur_offset = new_size;
        }
        self.offset = cur_offset;
        self.end_of_file = false;
        self.metadata.encrypted_plain.size = new_size;
        Ok(())
    }

    // clears the cache with all the plain data that was in it doesn't clear the metadata
    // and first node, which are part of the 'main' structure
    pub fn clear_cache(&mut self) -> Result<()> {
        if self.status.is_ok() {
            self.internal_flush(true)?;
        } else {
            // attempt to fix the file, will also flush it
            self.clear_error()?;
        }

        ensure!(self.status.is_ok(), Error::new(Errno::BadStatus));

        while let Some(node) = self.cache.pop_back() {
            if node.borrow().need_writing {
                bail!(Error::new(Errno::BadStatus));
            }
        }
        Ok(())
    }

    pub fn clear_error(&mut self) -> Result<()> {
        match self.status {
            FileStatus::Ok => {
                self.last_error = None;
                self.end_of_file = false;
            }
            FileStatus::WriteToDiskFailed => {
                self.write_to_disk(true)?;
                self.need_writing = false;
                self.set_file_status(FileStatus::Ok);
            }
            _ => {
                self.internal_flush(true)?;
                self.set_file_status(FileStatus::Ok);
            }
        }
        Ok(())
    }

    #[inline]
    pub fn get_metadata_mac(&mut self) -> Result<AeadMac> {
        self.flush()?;
        Ok(self.metadata.node.metadata.plaintext.gmac)
    }

    pub fn rename(&mut self, old_name: &str, new_name: &str) -> Result<()> {
        let old_len = old_name.len();
        ensure!(old_len > 0, Error::new(Errno::InvalidArgs));
        ensure!(old_len < FILENAME_MAX_LEN - 1, Error::with_msg(Errno::InvalidArgs, "file name too long"));

        let new_len = new_name.len();
        ensure!(new_len > 0, Error::new(Errno::InvalidArgs));
        ensure!(new_len < FILENAME_MAX_LEN - 1, Error::with_msg(Errno::InvalidArgs, "file name too long"));

        let meta_file_name = self.metadata.file_name()?;
        ensure!(
            meta_file_name == old_name,
            Error::with_msg(Errno::InvalidArgs, "file name mismatch")
        );

        self.metadata.encrypted_plain.file_name.fill(0);
        self.metadata.encrypted_plain.file_name[0..new_len].copy_from_slice(new_name.as_bytes());

        self.need_writing = true;
        Ok(())
    }
}

impl<D: BlockSet> FileInner<D> {
    #[inline]
    pub fn get_last_error(&self) -> Option<Error> {
        if self.last_error.is_some() && !self.status.is_ok() {
            Some(Error::new(Errno::BadStatus))
        } else {
            self.last_error.clone()
        }
    }

    #[inline]
    pub fn set_last_error(&mut self, error: Error) {
        self.last_error = Some(error);
    }


    #[inline]
    pub fn set_file_status(&mut self, status: FileStatus) {
        self.status = status;
    }
}
