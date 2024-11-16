use log::info;

use crate::{
    bail, ensure,
    layers::{bio::BlockLog, log::raw_log::RawLog},
    pfs::sys::{
        error::{FsError, FsResult, OsResult},
        node::NODE_SIZE,
    },
    BlockId, BlockSet, BufMut, BufRef, Errno, Error,
};

use super::HostFs;

#[derive(Debug)]
pub struct BlockFile<D> {
    raw_disk: D,
    size: usize,
}

impl<D: BlockSet> BlockFile<D> {
    pub fn create(raw_disk: D) -> Self {
        info!("created host file, range [{}, {})", 0, raw_disk.nblocks());
        let size = raw_disk.nblocks() * NODE_SIZE;
        Self { raw_disk, size }
    }
    pub fn read(&mut self, number: u64, buf: &mut [u8]) -> FsResult {
        ensure!(
            buf.len() == NODE_SIZE,
            FsError::Errno(Error::with_msg(
                Errno::NotBlockSizeAligned,
                "read buffer size not aligned to block size",
            ))
        );
        let buf_mut = BufMut::try_from(buf).map_err(|e| FsError::Errno(e))?;
        self.raw_disk
            .read(number as BlockId, buf_mut)
            .map_err(|e| FsError::Errno(e))
    }

    pub fn write(&mut self, number: u64, buf: &[u8]) -> FsResult {
        ensure!(
            buf.len() == NODE_SIZE,
            FsError::Errno(Error::with_msg(
                Errno::NotBlockSizeAligned,
                "write buffer size not aligned to block size",
            ))
        );
        let block_end = (number as usize + 1) * NODE_SIZE;
        self.size = block_end.max(self.size);

        let buf_ref = BufRef::try_from(buf).map_err(|e| FsError::Errno(e))?;
        self.raw_disk
            .write(number as BlockId, buf_ref)
            .map_err(|e| FsError::Errno(e))
    }

    pub fn flush(&mut self) -> FsResult {
        self.raw_disk.flush().map_err(|e| FsError::Errno(e))
    }

    pub fn size(&self) -> FsResult<usize> {
        Ok(self.raw_disk.nblocks() * NODE_SIZE)
    }
}

impl<D: BlockSet> HostFs for BlockFile<D> {
    fn read(&mut self, number: u64, node: &mut dyn AsMut<[u8]>) -> FsResult {
        self.read(number, node.as_mut())
    }

    fn write(&mut self, number: u64, node: &dyn AsRef<[u8]>) -> FsResult {
        self.write(number, node.as_ref())
    }

    fn flush(&mut self) -> FsResult {
        self.flush()
    }
}

pub struct RecoveryFile<D> {
    log: RawLog<D>,
}

impl<D: BlockSet> RecoveryFile<D> {
    pub fn new(log: RawLog<D>) -> Self {
        Self { log }
    }
}
