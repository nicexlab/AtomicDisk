mod cache;
pub mod error;
pub mod file;
mod host;
mod keys;
mod metadata;
mod node;

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

use error::FsResult;

use super::sgx::KeyPolicy;
use crate::os::{Box, SeekFrom};
use crate::pfs::sys::error::FsError;
use crate::pfs::sys::file::{self as file_imp, ProtectedFile};
use crate::{AeadKey, AeadMac, BlockSet};
use core::mem::ManuallyDrop;

#[derive(Clone, Debug)]
pub struct OpenOptions(file_imp::OpenOptions);

#[derive(Clone, Debug)]
pub enum EncryptMode {
    EncryptAutoKey(KeyPolicy),
    EncryptUserKey(AeadKey),
    IntegrityOnly,
}

impl OpenOptions {
    pub fn new() -> OpenOptions {
        Self(file_imp::OpenOptions::new())
    }
    #[inline]
    pub fn read(&mut self, read: bool) {
        self.0.read = read;
    }
    #[inline]
    pub fn write(&mut self, write: bool) {
        self.0.write = write;
    }
    #[inline]
    pub fn append(&mut self, append: bool) {
        self.0.append = append;
    }
    #[inline]
    pub fn update(&mut self, update: bool) {
        self.0.update = update;
    }
    #[inline]
    pub fn binary(&mut self, binary: bool) {
        self.0.binary = binary;
    }
}

impl Default for OpenOptions {
    fn default() -> OpenOptions {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SgxFile<D> {
    file: Box<ProtectedFile<D>>,
}

impl<D: BlockSet> SgxFile<D> {
    pub fn open(
        disk: D,
        path: &str,
        opts: &OpenOptions,
        encrypt_mode: &EncryptMode,
        cache_size: Option<usize>,
    ) -> FsResult<SgxFile<D>> {
        ProtectedFile::open(disk, path, &opts.0, &encrypt_mode.into(), cache_size)
            .map(|f| SgxFile { file: Box::new(f) })
    }

    pub fn create(
        disk: D,
        path: &str,
        opts: &OpenOptions,
        encrypt_mode: &EncryptMode,
        cache_size: Option<usize>,
    ) -> FsResult<SgxFile<D>> {
        ProtectedFile::create(disk, path, &opts.0, &encrypt_mode.into(), cache_size)
            .map(|f| SgxFile { file: Box::new(f) })
    }

    #[inline]
    pub fn read(&self, buf: &mut [u8]) -> FsResult<usize> {
        self.file.read(buf)
    }

    #[inline]
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> FsResult<usize> {
        self.file.read_at(buf, offset)
    }

    #[inline]
    pub fn write(&self, buf: &[u8]) -> FsResult<usize> {
        self.file.write(buf)
    }

    #[inline]
    pub fn write_at(&self, buf: &[u8], offset: u64) -> FsResult<usize> {
        self.file.write_at(buf, offset)
    }

    #[inline]
    pub fn tell(&self) -> FsResult<u64> {
        self.file.tell()
    }

    #[inline]
    pub fn seek(&self, pos: SeekFrom) -> FsResult<u64> {
        self.file.seek(pos)
    }

    #[inline]
    pub fn set_len(&self, size: u64) -> FsResult<()> {
        self.file.set_len(size)
    }

    #[inline]
    pub fn flush(&self) -> FsResult<()> {
        self.file.flush()
    }

    #[inline]
    pub fn file_size(&self) -> FsResult<u64> {
        self.file.file_size()
    }

    #[inline]
    pub fn is_eof(&self) -> bool {
        self.file.get_eof()
    }

    #[allow(dead_code)]
    #[inline]
    pub fn get_error(&self) -> FsError {
        self.file.get_error()
    }

    #[inline]
    pub fn clear_cache(&self) -> FsResult<()> {
        self.file.clear_cache()
    }

    #[inline]
    pub fn clear_error(&self) -> FsResult<()> {
        self.file.clear_error()
    }

    #[inline]
    pub fn get_mac(&self) -> FsResult<AeadMac> {
        self.file.get_metadata_mac()
    }

    #[inline]
    pub fn rename<P: AsRef<str>, Q: AsRef<str>>(&self, old_name: P, new_name: Q) -> FsResult<()> {
        self.file.rename(old_name, new_name)
    }
}
