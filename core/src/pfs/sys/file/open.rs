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

use crate::layers::bio::MemDisk;
use crate::os::Arc;
use crate::os::HashMap;
use crate::pfs::sys::cache::LruCache;
use crate::pfs::sys::error::{
    FsError, FsResult, SgxStatus, EACCES, EINVAL, ENAMETOOLONG, ENOENT, ENOTSUP,
};
use crate::pfs::sys::file::{FileInner, FileStatus, OpenMode, OpenOptions};
use crate::pfs::sys::host::block_file::BlockFile;
use crate::pfs::sys::host::journal::RecoveryJournal;
use crate::pfs::sys::host::{self, HostFs, RecoveryHandler, RECOVERY_NODE_SIZE};
use crate::pfs::sys::keys::{FsKeyGen, RestoreKey};
use crate::pfs::sys::metadata::MetadataInfo;
use crate::pfs::sys::metadata::{
    FILENAME_MAX_LEN, FULLNAME_MAX_LEN, MD_USER_DATA_SIZE, SGX_FILE_ID, SGX_FILE_MAJOR_VERSION,
};
use crate::pfs::sys::node::{FileNode, FileNodeRef, NodeType, NODE_SIZE};
use crate::{bail, ensure, eos, AeadKey, BlockSet};
use core::cell::RefCell;
use crate::prelude::*;

pub const SE_PAGE_SIZE: usize = 0x1000;
macro_rules! is_page_aligned {
    ($num:expr) => {
        $num & (SE_PAGE_SIZE - 1) == 0
    };
}

pub const DEFAULT_CACHE_SIZE: usize = 2400 * SE_PAGE_SIZE;

impl<D: BlockSet> FileInner<D> {
    pub fn open(
        path: &str,
        disk: D,
        opts: &OpenOptions,
        mode: &OpenMode,
        cache_size: Option<usize>,
    ) -> FsResult<Self> {
        let cache_size = Self::check_cache_size(cache_size)?;
        let file_name = path;
        let key_gen = FsKeyGen::new(mode)?;

        let mut host_file = BlockFile::create(Self::subdisk_for_data(&disk)?);
        let mut journal = RecoveryJournal::create(Self::subdisk_for_journal(&disk)?);

        let mut offset = 0;
        let (metadata, root_mht, rollback_nodes) = {
            let (metadata, root_mht, rollback_nodes) =
                match Self::open_file(&mut host_file, file_name, &key_gen, mode) {
                    Ok((_metadata, _root_mht)) => {
                        // use recovery file to discard all uncommitted nodes
                        let rollback_nodes =
                            Self::recover_and_reopen_file(&mut host_file, &mut journal)?;
                        let (metadata, root_mht) =
                            Self::open_file(&mut host_file, file_name, &key_gen, mode)?;
                        (metadata, root_mht, rollback_nodes)
                    }
                    Err(e) if e.equal_to_sgx_error(SgxStatus::RecoveryNeeded) => {
                        let rollback_nodes =
                            Self::recover_and_reopen_file(&mut host_file, &mut journal)?;

                        let (metadata, root_mht) =
                            Self::open_file(&mut host_file, file_name, &key_gen, mode)?;
                        (metadata, root_mht, rollback_nodes)
                    }
                    Err(e) => bail!(e),
                };

            if opts.append && !opts.update {
                offset = metadata.encrypted_plain.size;
            }
            (metadata, root_mht, rollback_nodes)
        };

        let mut protected_file = Self {
            host_file,
            metadata,
            root_mht,
            key_gen,
            opts: *opts,
            need_writing: false,
            end_of_file: false,
            max_cache_page: cache_size,
            offset,
            last_error: FsError::SgxError(SgxStatus::Success),
            status: FileStatus::NotInitialized,
            journal,
            cache: LruCache::new(cache_size),
        };
        if !rollback_nodes.is_empty() {
            protected_file.rollback_nodes(rollback_nodes)?;
        }
        protected_file.status = FileStatus::Ok;
        Ok(protected_file)
    }

    pub fn create(
        path: &str,
        disk: D,
        opts: &OpenOptions,
        mode: &OpenMode,
        cache_size: Option<usize>,
    ) -> FsResult<Self> {
        let cache_size = Self::check_cache_size(cache_size)?;
        let file_name = path;
        // Self::check_open_param(path, file_name, opts, mode)?;

        let key_gen = FsKeyGen::new(mode)?;

        //Self::check_file_exist(opts, mode, path)?;
        // 10MB
        let host_file = BlockFile::create(Self::subdisk_for_data(&disk)?);
        let journal = RecoveryJournal::create(Self::subdisk_for_journal(&disk)?);
        let need_writing = true;
        let (metadata, root_mht, rollback_nodes) = {
            let metadata = Self::new_file(file_name, mode)?;
            (
                metadata,
                FileNode::new_root_ref(mode.into()),
                HashMap::new(),
            )
        };

        let mut protected_file = Self {
            host_file,
            metadata,
            root_mht,
            key_gen,
            opts: *opts,
            need_writing,
            end_of_file: false,
            max_cache_page: cache_size,
            offset: 0,
            last_error: FsError::SgxError(SgxStatus::Success),
            status: FileStatus::NotInitialized,
            journal,
            cache: LruCache::new(cache_size),
        };
        if !rollback_nodes.is_empty() {
            protected_file.rollback_nodes(rollback_nodes)?;
        }
        protected_file.status = FileStatus::Ok;
        Ok(protected_file)
    }

    fn open_file(
        host_file: &mut dyn HostFs,
        file_name: &str,
        key_gen: &dyn RestoreKey,
        mode: &OpenMode,
    ) -> FsResult<(MetadataInfo, FileNodeRef)> {
        let mut metadata = MetadataInfo::default();
        metadata.read_from_disk(host_file)?;

        ensure!(
            metadata.node.metadata.plaintext.file_id == SGX_FILE_ID,
            FsError::SgxError(SgxStatus::NotSgxFile)
        );
        ensure!(
            metadata.node.metadata.plaintext.major_version == SGX_FILE_MAJOR_VERSION,
            eos!(ENOTSUP)
        );
        ensure!(
            !metadata.update_flag(),
            FsError::SgxError(SgxStatus::RecoveryNeeded)
        );

        let encrypt_flags = mode.into();
        ensure!(encrypt_flags == metadata.encrypt_flags(), eos!(EINVAL));

        let key_policy = mode.key_policy();
        if mode.is_auto_key() {
            ensure!(key_policy.unwrap() == metadata.key_policy(), eos!(EINVAL));
        }

        let key = match mode.import_key() {
            Some(key) => {
                metadata.set_key_policy(key_policy.unwrap());
                *key
            }
            None => metadata.restore_key(key_gen)?,
        };
        metadata.decrypt(&key)?;

        let meta_file_name = metadata.file_name()?;
        ensure!(
            meta_file_name == file_name,
            FsError::SgxError(SgxStatus::NameMismatch)
        );

        let mut root_mht = FileNode::new_root(encrypt_flags);
        if metadata.encrypted_plain.size > MD_USER_DATA_SIZE {
            root_mht.read_from_disk(host_file)?;
            root_mht.decrypt(
                &metadata.encrypted_plain.mht_key,
                &metadata.encrypted_plain.mht_gmac,
            )?;
            root_mht.new_node = false;
        }
        Ok((metadata, FileNode::build_ref(root_mht)))
    }

    #[inline]
    fn new_file(file_name: &str, mode: &OpenMode) -> FsResult<MetadataInfo> {
        let mut metadata = MetadataInfo::new();

        metadata.set_encrypt_flags(mode.into());
        if let Some(key_policy) = mode.key_policy() {
            metadata.set_key_policy(key_policy);
        }
        metadata.encrypted_plain.file_name[0..file_name.len()]
            .copy_from_slice(file_name.as_bytes());

        Ok(metadata)
    }

    pub fn rollback_nodes(
        &mut self,
        rollback_nodes: HashMap<u64, Arc<RefCell<FileNode>>>,
    ) -> FsResult<()> {
        for (physical_number, data_node) in rollback_nodes {
            assert!(Self::is_data_node(physical_number));

            data_node.borrow_mut().encrypt_flags = self.metadata.encrypt_flags();

            let mht_logical_number = RecoveryHandler::calculate_mht_logical_number(physical_number);

            let parent_mht = self.get_mht_node_by_logic_number(mht_logical_number)?;
            // udpated the parent of data node
            data_node.borrow_mut().parent = Some(parent_mht);

            self.rollback_data_node(physical_number, data_node)?;

            // Only rollback data nodes, mht nodes should be calculated by data nodes' key and mac
        }
        Ok(())
    }

    #[inline]
    fn recover_and_reopen_file(
        host_file: &mut BlockFile<D>,
        journal: &mut RecoveryJournal<D>,
    ) -> FsResult<HashMap<u64, Arc<RefCell<FileNode>>>> {
        // let file_size = host_file.size()?;
        // let n_blocks = file_size / NODE_SIZE;

        // recovery file does not exist,all committed nodes are persisted on disk and all uncommitted nodes are discarded
        // if !Self::files_exist(recovery_path)? {
        //     return Ok((
        //         BlockFile::create(MemDisk::create(n_blocks)?),
        //         HashMap::new(),
        //     ));
        // }
        // TODO check recovery file size

        let roll_back_nodes = host::journal::recovery(host_file, journal)?;
        // ensure!(
        //     host_file.size() == file_size,
        //     FsError::SgxError(SgxStatus::Unexpected)
        // );
        Ok(roll_back_nodes)
    }

    fn files_exist(_path: &str) -> FsResult<bool> {
        unreachable!()
        // host::raw_file::try_exists(path)
    }

    fn check_file_exist(_opts: &OpenOptions, _mode: &OpenMode, _path: &str) -> FsResult {
        unreachable!()
        // let is_exist = host::raw_file::try_exists(path)?;

        // if opts.read || mode.import_key().is_some() {
        //     ensure!(is_exist, eos!(ENOENT));
        // }
        // if opts.write && is_exist {
        //     // try to delete existing file
        //     host::raw_file::remove(path)?;
        //     // re-check
        //     let is_exist = host::raw_file::try_exists(path)?;
        //     ensure!(!is_exist, eos!(EACCES));
        // }
    }

    #[inline]
    fn check_open_param(path: &str, name: &str, opts: &OpenOptions, mode: &OpenMode) -> FsResult {
        let path_len = path.len();
        ensure!(
            (path_len > 0 && path_len < FULLNAME_MAX_LEN - 1),
            eos!(EINVAL)
        );

        let name_len = name.len();
        ensure!(name_len > 0, eos!(EINVAL));
        ensure!(name_len < FILENAME_MAX_LEN - 1, eos!(ENAMETOOLONG));

        opts.check()?;
        mode.check()?;

        // if let Some(key) = mode.import_key() {
        //     ensure!(key.ct_ne(&AeadKey::default()), eos!(EINVAL));
        // }
        Ok(())
    }

    #[inline]
    fn check_cache_size(cache_size: Option<usize>) -> FsResult<usize> {
        cache_size
            .or(Some(DEFAULT_CACHE_SIZE))
            .and_then(|cache_size| {
                if is_page_aligned!(cache_size) {
                    Some(cache_size / SE_PAGE_SIZE)
                } else {
                    None
                }
            })
            .ok_or_else(|| eos!(EINVAL))
    }

    fn subdisk_for_data(disk: &D) -> FsResult<D> {
        disk.subset(0..disk.nblocks() * 7 / 8)
            .map_err(|e| FsError::Errno(e))
    }

    fn subdisk_for_journal(disk: &D) -> FsResult<D> {
        disk.subset(disk.nblocks() * 7 / 8..disk.nblocks())
            .map_err(|e| FsError::Errno(e))
    }
}
