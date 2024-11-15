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

pub mod block_file;
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

    pub fn is_mht_node(physical_number: u64) -> bool {
        if physical_number <= 1 {
            // node 0 is metadata node,
            // node 1 is mht root node
            return true;
        }

        // For nodes starting from 2:
        // - Each group contains ATTACHED_DATA_NODES_COUNT + 1 nodes
        // - In each group, first node is MHT node, followed by ATTACHED_DATA_NODES_COUNT data nodes
        // Example:
        // - node 0: metadata node
        // - node 1: MHT root node
        // - node 2-97: data nodes (96 nodes)
        // - node 98: MHT node
        // - node 99-194: data nodes
        // And so on...
        let adjusted_number = physical_number - 1;
        let position_in_group = adjusted_number % (ATTACHED_DATA_NODES_COUNT + 1);

        // If position in group is not 0 (not MHT node), then it's a data node
        position_in_group == 0
    }
    pub fn push_raw_mht(&mut self, physical_number: u64, mht_data: [u8; NODE_SIZE]) {
        let encrypted_data = EncryptedData { data: mht_data };
        self.raw_mhts.insert(physical_number, encrypted_data);
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

    pub fn calculate_mht_logical_number(physical_number: u64) -> u64 {
        let mht_logic_number = (physical_number - 2) / (ATTACHED_DATA_NODES_COUNT + 1);
        mht_logic_number
    }

    pub fn calculate_data_logical_number(physical_number: u64) -> u64 {
        let mht_logic_number = (physical_number - 2) / (ATTACHED_DATA_NODES_COUNT + 1);
        let data_logic_number = physical_number - 2 - mht_logic_number;
        data_logic_number
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
        self.mhts.insert(physical_number, mht_node.clone());

        mht_node
    }

    fn decrypt_node(
        &mut self,
        physical_number: u64,
        node: EncryptedData,
    ) -> Arc<RefCell<FileNode>> {
        let mht_logical_number = Self::calculate_mht_logical_number(physical_number);
        let data_logical_number = Self::calculate_data_logical_number(physical_number);

        let encrypt_flags = EncryptFlags::UserKey;
        let mht_node = self.get_mht_node(mht_logical_number, encrypt_flags);

        let mut data_node = FileNode::new(
            NodeType::Data,
            data_logical_number,
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

mod tests {
    use core::cell::RefCell;
    use std::sync::Arc;

    use hashbrown::HashMap;

    use crate::{
        pfs::sys::{
            file::OpenMode,
            metadata::{EncryptFlags, MetadataInfo},
            node::{EncryptedData, FileNode, NodeType},
        },
        AeadKey,
    };

    use super::RecoveryHandler;

    fn new_file(file_name: &str, mode: &OpenMode) -> MetadataInfo {
        let mut metadata = MetadataInfo::new();

        metadata.set_encrypt_flags(mode.into());
        if let Some(key_policy) = mode.key_policy() {
            metadata.set_key_policy(key_policy);
        }
        metadata.encrypted_plain.file_name[0..file_name.len()]
            .copy_from_slice(file_name.as_bytes());

        metadata
    }

    #[test]
    fn test_calculate_logical_number() {
        let logical_number = RecoveryHandler::calculate_data_logical_number(2);
        assert_eq!(logical_number, 0);

        let logical_number = RecoveryHandler::calculate_data_logical_number(3);
        assert_eq!(logical_number, 1);

        let logical_number = RecoveryHandler::calculate_data_logical_number(99);
        assert_eq!(logical_number, 96);

        let logical_number = RecoveryHandler::calculate_data_logical_number(195);
        assert_eq!(logical_number, 192);

        let logical_number = RecoveryHandler::calculate_data_logical_number(197);
        assert_eq!(logical_number, 193);
    }

    fn init_mht(data: [u8; 4096]) -> (HashMap<u64, EncryptedData>, Arc<RefCell<FileNode>>) {
        let open_mode = OpenMode::UserKey(AeadKey::default());
        let key = AeadKey::default();
        let mut meta = new_file("test", &open_mode);

        let root_mht =
            FileNode::build_ref(FileNode::new(NodeType::Mht, 0, 1, EncryptFlags::UserKey));
        let mht1 = FileNode::build_ref(FileNode::new(NodeType::Mht, 1, 98, EncryptFlags::UserKey));

        let data_node =
            FileNode::build_ref(FileNode::new(NodeType::Data, 96, 99, EncryptFlags::UserKey));

        data_node.borrow_mut().parent = Some(mht1.clone());
        mht1.borrow_mut().parent = Some(root_mht.clone());

        let mut data_node_guard = data_node.borrow_mut();
        data_node_guard.plaintext.as_mut()[0..4096].copy_from_slice(&data);
        data_node_guard.need_writing = true;
        data_node_guard.new_node = true;
        data_node_guard.encrypt_flags = EncryptFlags::UserKey;
        data_node_guard.encrypt(&key).unwrap();

        drop(data_node_guard);

        mht1.borrow_mut().encrypt(&key).unwrap();
        let mac = root_mht.borrow_mut().encrypt(&key).unwrap();

        meta.encrypted_plain.mht_key = key;
        meta.encrypted_plain.mht_gmac = mac;
        meta.encrypt(&key).unwrap();

        let mut raw_mhts = HashMap::new();
        raw_mhts.insert(
            0,
            EncryptedData {
                data: meta.node.metadata.as_ref().to_vec().try_into().unwrap(),
            },
        );
        raw_mhts.insert(1, root_mht.borrow().ciphertext.node_data.clone());
        raw_mhts.insert(98, mht1.borrow().ciphertext.node_data.clone());

        (raw_mhts, data_node)
    }

    #[test]
    fn test_init_mhts() {
        let (raw_mhts, _) = init_mht([1; 4096]);
        let _recovery_handler = RecoveryHandler::new(raw_mhts);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let (raw_mhts, _) = init_mht([1; 4096]);
        let key = AeadKey::default();
        let meta_data = raw_mhts.get(&0).unwrap();
        let mut meta_info = MetadataInfo::new();
        meta_info
            .node
            .metadata
            .as_mut()
            .copy_from_slice(meta_data.data.as_slice());
        meta_info.decrypt(&key).unwrap();

        let key = meta_info.encrypted_plain.mht_key;
        let mac = meta_info.encrypted_plain.mht_gmac;

        let root_mht_data = raw_mhts.get(&1).unwrap();

        let mut root_mht = FileNode::new(NodeType::Mht, 0, 1, EncryptFlags::UserKey);
        root_mht.ciphertext.node_data = root_mht_data.clone();
        root_mht.decrypt(&key, &mac).unwrap();

        let root_mht = FileNode::build_ref(root_mht);

        let mht1_data = raw_mhts.get(&98).unwrap();

        let mut mht1 = FileNode::new(NodeType::Mht, 1, 98, EncryptFlags::UserKey);
        mht1.ciphertext.node_data = mht1_data.clone();
        mht1.parent = Some(root_mht.clone());

        let gcm_data = mht1.get_gcm_data().unwrap();
        mht1.decrypt(&gcm_data.key, &gcm_data.mac).unwrap();

        let _mht1 = FileNode::build_ref(mht1);
    }
    #[test]
    fn test_get_node() {
        let (raw_mhts, _) = init_mht([1; 4096]);
        let mut recovery_handler = RecoveryHandler::new(raw_mhts);

        let _node = recovery_handler.get_mht_node(1, EncryptFlags::UserKey);
        let _node = recovery_handler.get_mht_node(0, EncryptFlags::UserKey);
    }

    #[test]
    fn test_decrypt_data_node() {
        let data = [1; 4096];
        let (raw_mhts, data_node) = init_mht(data.clone());
        let mut recovery_handler = RecoveryHandler::new(raw_mhts);

        let node =
            recovery_handler.decrypt_node(99, data_node.borrow().ciphertext.node_data.clone());
        assert_eq!(node.borrow().plaintext.as_ref(), data.as_slice());
    }
}
