use super::{block_file::BlockFile, HostFs, JournalFlag};
use crate::os::Arc;
use crate::os::HashMap;
use crate::{
    bail, ensure,
    layers::disk,
    pfs::sys::{
        host::{RecoveryHandler, RECOVERY_NODE_SIZE},
        node::{EncryptedData, FileNode, NodeType, NODE_SIZE},
    },
    BlockSet, Buf, Errno, Error, BLOCK_SIZE,
};
use core::{cell::RefCell, ffi::CStr};
use crate::prelude::*;

// 4MB
const DEFAULT_BUF_SIZE: usize = 4 * 1024 * 1024;
// the first block is used to store the journal meta, currently only the length
const INNER_OFFSET: usize = 1 * BLOCK_SIZE;

#[derive(Debug)]
pub struct RawJournal<D> {
    buf: Vec<u8>,
    flush_pos: usize,
    disk: D,
}

impl<D: BlockSet> RawJournal<D> {
    pub fn create(disk: D) -> RawJournal<D> {
        Self {
            buf: Vec::with_capacity(DEFAULT_BUF_SIZE),
            flush_pos: INNER_OFFSET,
            disk,
        }
    }

    pub fn append(&mut self, data: &[u8]) -> Result<()> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= DEFAULT_BUF_SIZE {
            self.flush()?
        }
        Ok(())
    }

    // read is only used for recovery, so we don't need to check if the data is in the buffer
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<()> {
        self.disk.read_slice(offset + INNER_OFFSET, buf)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        let offset = self.flush_pos;
        self.flush_pos = offset + self.buf.len();
        if !self.buf.is_empty() {
            self.disk.write_slice(offset, &self.buf)?;
        }
        // update the journal meta
        self.disk.write_slice(0, &self.flush_pos.to_le_bytes())?;
        self.disk.flush()?;
        self.buf.clear();
        Ok(())
    }

    pub fn size(&self) -> Result<usize> {
        let mut buf = Buf::alloc(1)?;
        self.disk.read(0, buf.as_mut())?;
        let size = usize::from_le_bytes(buf.as_slice()[0..8].try_into().unwrap());
        ensure!(
            size >= INNER_OFFSET,
            Error::with_msg(
                Errno::InvalidArgs,
                "journal size is less than inner offset"
            )
        );
        Ok(size - INNER_OFFSET)
    }

    pub fn reset(&mut self) -> Result<()> {
        self.buf.clear();
        self.flush_pos = INNER_OFFSET;
        self.disk.write_slice(0, &self.flush_pos.to_le_bytes())?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct RecoveryJournal<D> {
    raw: RawJournal<D>,
}

impl<D: BlockSet> RecoveryJournal<D> {
    pub fn create(disk: D) -> RecoveryJournal<D> {
        #[cfg(not(feature = "linux"))]
        info!(
            "created recovery journal, range [{}, {})",
            0,
            disk.nblocks()
        );

        Self {
            raw: RawJournal::create(disk),
        }
    }

    pub fn append(&mut self, data: &[u8]) -> Result<()> {
        ensure!(
            data.len() == RECOVERY_NODE_SIZE,
            Error::with_msg(
                Errno::InvalidArgs,
                "recovery node size is not equal to recovery node size",
            )   
        );
        let flag = JournalFlag::Node;
        self.raw.append(&[flag as u8])?;
        self.raw.append(data)
    }

    pub fn commit(&mut self) -> Result<()> {
        let flag = JournalFlag::Commit;
        self.raw.append(&[flag as u8])?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.raw.flush()
    }
    pub fn size(&self) -> Result<usize> {
        self.raw.size()
    }

    pub fn read_inner(&self, offset: usize, buf: &mut [u8]) -> Result<()> {
        self.raw.read(offset, buf)
    }

    pub fn reset(&mut self) -> Result<()> {
        self.raw.reset()
    }
}

impl<D: BlockSet> HostFs for RecoveryJournal<D> {
    fn flush(&mut self) -> Result<()> {
        self.flush()
    }

    fn read(&mut self, _number: u64, _node: &mut dyn AsMut<[u8]>) -> Result<()> {
        return_errno!(Errno::Unsupported)
    }

    fn write(&mut self, _number: u64, node: &dyn AsRef<[u8]>) -> Result<()> {
        self.append(node.as_ref())
    }
}

pub fn recovery<D: BlockSet>(
    source: &mut BlockFile<D>,
    recovery: &mut RecoveryJournal<D>,
) -> Result<HashMap<u64, Arc<RefCell<FileNode>>>> {
    let log_size = recovery.size()?;
    let mut offset = 0;
    let mut last_commit_offset = offset;

    let mut flag_buf = vec![0u8; 1];

    while offset < log_size {
        recovery.read_inner(offset, flag_buf.as_mut_slice())?;
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

    offset = 0;
    let mut recovery_handler = RecoveryHandler::new(HashMap::new());
    let mut data_buf = [0_u8; RECOVERY_NODE_SIZE];

    let mut rollback_nodes = HashMap::new();

    while offset < log_size {
        let mut left_size = log_size - offset;
        if left_size < 1 {
            break;
        }
        recovery.read_inner(offset, flag_buf.as_mut_slice())?;
        let flag: JournalFlag = flag_buf[0].into();
        offset += 1;
        left_size -= 1;

        match flag {
            JournalFlag::Node => {
                if left_size < RECOVERY_NODE_SIZE {
                    break;
                }
                recovery.read_inner(offset, data_buf.as_mut_slice())?;

                let mut number = [0u8; 8];
                number.copy_from_slice(&data_buf[0..8]);
                let physical_node_number = u64::from_ne_bytes(number);

                if RecoveryHandler::is_mht_node(physical_node_number) {
                    recovery_handler
                        .push_raw_mht(physical_node_number, data_buf[8..].try_into().unwrap());
                }
                offset += RECOVERY_NODE_SIZE;
                if offset >= last_commit_offset {
                    // record the first version of data node
                    if !rollback_nodes.contains_key(&physical_node_number)
                        && !RecoveryHandler::is_mht_node(physical_node_number)
                    {
                        #[cfg(not(feature = "linux"))]
                        debug!("insert committed node: {}", physical_node_number);
                        let encrypted_data = EncryptedData {
                            data: data_buf[8..].try_into().unwrap(),
                        };
                        let data_node =
                            recovery_handler.decrypt_node(physical_node_number, encrypted_data);
                        rollback_nodes.insert(physical_node_number, data_node);
                    }
                }
                source.write(physical_node_number, &data_buf[8..])?;
            }
            JournalFlag::Commit => {
                // do nothing
            }
        }
    }
    source.flush()?;
    Ok(rollback_nodes)
}

mod tests {
    use crate::{
        layers::bio::{MemDisk, BID_SIZE},
        pfs::sys::{
            host::{
                block_file::BlockFile,
                journal::{recovery, RawJournal},
                RECOVERY_NODE_SIZE,
            },
            node::NODE_SIZE,
        },
        BlockSet, BLOCK_SIZE,
    };

    use super::{RecoveryJournal, DEFAULT_BUF_SIZE, INNER_OFFSET};

    #[test]
    fn read_write_in_buf() {
        let disk = MemDisk::create(128).unwrap();
        let mut journal = RawJournal::create(disk);
        journal.append(b"hello").unwrap();
        journal.append(b"world").unwrap();
        journal.flush().unwrap();
        let mut buf = vec![0u8; 5];
        journal.read(5, &mut buf).unwrap();
        assert_eq!(buf, b"world");
    }

    #[test]
    fn trigger_flush() {
        let disk_size = DEFAULT_BUF_SIZE * 2;
        let disk = MemDisk::create(disk_size).unwrap();
        let mut journal = RawJournal::create(disk);

        // each buf is 4KB, write enough to trigger flush
        for i in 0..(disk_size / BLOCK_SIZE) {
            let buf = vec![i as u8; BLOCK_SIZE];
            journal.append(&buf).unwrap();
        }
        journal.flush().unwrap();
        let size = journal.size().unwrap();
        // meta block(4KB) + data blocks
        assert_eq!(size, disk_size);

        for i in 0..(disk_size / BLOCK_SIZE) {
            let mut buf = vec![0u8; BLOCK_SIZE];
            journal.read(i * BLOCK_SIZE, &mut buf).unwrap();
            assert_eq!(buf, vec![i as u8; BLOCK_SIZE]);
        }
    }

    #[test]
    fn recovery_read_write() {
        let disk_size = DEFAULT_BUF_SIZE * 2;
        let disk = MemDisk::create(disk_size).unwrap();
        let mut journal = RecoveryJournal::create(disk);

        let recovery_block = vec![0u8; RECOVERY_NODE_SIZE];
        journal.append(&recovery_block).unwrap();
        journal.commit().unwrap();
        journal.flush().unwrap();

        let size = journal.raw.size().unwrap();
        // data blocks + journal flag(1B) * 2
        let expected_size = RECOVERY_NODE_SIZE + 2;
        assert_eq!(size, expected_size);
    }

    #[test]
    fn simple_recovery() {
        let disk_size = DEFAULT_BUF_SIZE * 2;
        let block_num = disk_size / BLOCK_SIZE;
        let disk = MemDisk::create(disk_size).unwrap();

        let data_end = 3 * (BLOCK_SIZE * block_num / 4);
        let data_disk = disk.subset(0..data_end).unwrap();
        let journal_disk = disk.subset(data_end..disk_size).unwrap();
        let mut data_file = BlockFile::create(data_disk);
        let mut journal = RecoveryJournal::create(journal_disk);

        let round = 10;
        for i in 0..round {
            let mut recovery_block = vec![i as u8; RECOVERY_NODE_SIZE];
            recovery_block.as_mut_slice()[0..8].copy_from_slice(&(i as u64).to_ne_bytes());
            journal.append(&recovery_block).unwrap();
        }
        journal.commit().unwrap();
        journal.flush().unwrap();

        let rollback_nodes = recovery(&mut data_file, &mut journal).unwrap();
        assert_eq!(rollback_nodes.len(), 0);
        for i in 0..round {
            let recovery_block = vec![i as u8; RECOVERY_NODE_SIZE];
            let mut buf = vec![0u8; NODE_SIZE];
            data_file.read(i, &mut buf).unwrap();
            assert_eq!(buf, recovery_block[8..]);
        }
    }
}
