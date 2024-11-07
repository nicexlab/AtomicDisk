use super::error::{FsError, FsResult, OsResult};
use super::metadata::{EncryptFlags, MetadataInfo, MD_USER_DATA_SIZE};
use super::node::{
    EncryptedData, FileNode, NodeType, ATTACHED_DATA_NODES_COUNT, CHILD_MHT_NODES_COUNT, NODE_SIZE,
};
use crate::pfs::sys::error::ENOTSUP;
use crate::{bail, eos};
use crate::{ensure, AeadKey};
use core::cell::RefCell;
use hashbrown::HashMap;
use libc::c_void;
use raw_file::RawFile;
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Error, ErrorKind, SeekFrom};
use std::mem::{self, ManuallyDrop};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::path::Path;
use std::sync::Arc;

pub mod journal;
pub mod raw_file;

const MILISECONDS_SLEEP_FOPEN: u32 = 10;
const MAX_FOPEN_RETRIES: usize = 10;
pub const RECOVERY_NODE_SIZE: usize = mem::size_of::<u64>() + NODE_SIZE;

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

pub struct RecoveryHandler {
    raw_mhts: HashMap<u64, EncryptedData>,
    mhts: HashMap<u64, Arc<RefCell<FileNode>>>,
}

impl RecoveryHandler {
    pub fn new(raw_mhts: HashMap<u64, EncryptedData>) -> Self {
        Self {
            raw_mhts,
            mhts: HashMap::new(),
        }
    }

    fn get_node_numbers(offset: usize) -> (u64, u64, u64, u64) {
        if offset < MD_USER_DATA_SIZE {
            return (0, 0, 0, 0);
        }

        // node 0 - meta data node
        // node 1 - mht
        // nodes 2-97 - data (ATTACHED_DATA_NODES_COUNT == 96)
        // node 98 - mht
        // node 99-195 - data
        // etc.
        let data_logic_number = ((offset - MD_USER_DATA_SIZE) / NODE_SIZE) as u64;
        let mht_logic_number = data_logic_number / ATTACHED_DATA_NODES_COUNT;

        // + 1 - meta data node
        // + 1 - mht root
        // + mht_logic_number - number of mht nodes in the middle (the root mht mht_node_number is 0)
        let data_physical_number = data_logic_number + 1 + 1 + mht_logic_number;

        let mht_physical_number =
            data_physical_number - data_logic_number % ATTACHED_DATA_NODES_COUNT - 1;

        (
            mht_logic_number,
            data_logic_number,
            mht_physical_number,
            data_physical_number,
        )
    }

    pub fn get_data_node_numbers(offset: usize) -> (u64, u64) {
        let (_, logic, _, physical) = Self::get_node_numbers(offset);
        (logic, physical)
    }

    fn get_mht_node_numbers(offset: usize) -> (u64, u64) {
        let (logic, _, physical, _) = Self::get_node_numbers(offset);
        (logic, physical)
    }

    fn get_mht_node(
        &mut self,
        logical_number: u64,
        encrypt_flags: EncryptFlags,
    ) -> Arc<RefCell<FileNode>> {
        if logical_number == 0 {
            let physical_number = 1;

            if let Some(mht_node) = self.mhts.get(&physical_number) {
                return mht_node.clone();
            }

            let mut root_mht = FileNode::new(
                NodeType::Mht,
                logical_number,
                physical_number,
                encrypt_flags,
            );
            root_mht.ciphertext.node_data = self.raw_mhts.get(&physical_number).unwrap().clone();

            let mut meta_info = MetadataInfo::default();

            meta_info
                .node
                .metadata
                .as_mut()
                .copy_from_slice(self.raw_mhts.get(&0).unwrap().data.as_slice());

            // TODO: get key from KeyGen
            let key = AeadKey::default();

            meta_info.decrypt(&key).unwrap();

            root_mht
                .decrypt(
                    &meta_info.encrypted_plain.mht_key,
                    &meta_info.encrypted_plain.mht_gmac,
                )
                .unwrap();

            let root_mht = FileNode::build_ref(root_mht);
            self.mhts.insert(physical_number, root_mht.clone());
            return root_mht;
        }

        let physical_number = 1 + logical_number * (ATTACHED_DATA_NODES_COUNT + 1);

        if let Some(mht_node) = self.mhts.get(&physical_number) {
            return mht_node.clone();
        }

        let parent_mht_node =
            self.get_mht_node((logical_number - 1) / CHILD_MHT_NODES_COUNT, encrypt_flags);

        let mut mht_node = FileNode::new(
            NodeType::Mht,
            logical_number,
            physical_number,
            encrypt_flags,
        );
        mht_node.parent = Some(parent_mht_node);
        mht_node.ciphertext.node_data = self.raw_mhts.get(&physical_number).unwrap().clone();

        let gcm_data = mht_node.get_gcm_data().unwrap();

        mht_node.decrypt(&gcm_data.key, &gcm_data.mac).unwrap();

        let mht_node = FileNode::build_ref(mht_node);

        mht_node
    }

    fn decrypt_node(
        &mut self,
        disk_physical_number: u64,
        node: EncryptedData,
    ) -> Arc<RefCell<FileNode>> {
        let source_offset = disk_physical_number * NODE_SIZE as u64;
        let (logical_number, physical_number) = Self::get_data_node_numbers(source_offset as usize);
        assert!(physical_number == disk_physical_number);

        let encrypt_flags = EncryptFlags::UserKey;
        let mht_node = self.get_mht_node(logical_number, encrypt_flags);

        let mut data_node = FileNode::new(
            NodeType::Data,
            logical_number,
            physical_number,
            encrypt_flags,
        );

        data_node.parent = Some(mht_node);
        data_node.ciphertext.node_data = node;

        let gcm_data = data_node.get_gcm_data().unwrap();
        data_node.decrypt(&gcm_data.key, &gcm_data.mac).unwrap();

        let data_node = FileNode::build_ref(data_node);
        data_node
    }
}
