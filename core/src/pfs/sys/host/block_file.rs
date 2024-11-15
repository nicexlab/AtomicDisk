use crate::{
    bail, ensure,
    layers::{bio::BlockLog, log::raw_log::RawLog},
    pfs::sys::{
        error::{FsError, FsResult, OsResult},
        node::NODE_SIZE,
    },
    BlockId, BlockSet, BufMut, BufRef, Errno,
};

pub struct BlockFile<D: BlockSet> {
    raw_disk: D,
    offset: usize,
    size: usize,
}

impl<D: BlockSet> BlockFile<D> {
    pub fn new(raw_disk: D, offset: usize, length: usize) -> Self {
        Self {
            raw_disk,
            offset,
            size: length,
        }
    }
    pub fn read(&mut self, number: u64, buf: &mut [u8]) -> FsResult {
        ensure!(
            buf.len() == NODE_SIZE,
            FsError::Errno(Errno::NotBlockSizeAligned)
        );
        let buf_mut = BufMut::try_from(buf).map_err(|e| FsError::Errno(e.errno()))?;
        self.raw_disk
            .read(number as BlockId, buf_mut)
            .map_err(|e| FsError::Errno(e.errno()))
    }

    pub fn write(&mut self, number: u64, buf: &[u8]) -> FsResult {
        ensure!(
            buf.len() == NODE_SIZE,
            FsError::Errno(Errno::NotBlockSizeAligned)
        );
        let block_end = (number as usize + 1) * NODE_SIZE;
        self.size = block_end.max(self.size);

        let buf_ref = BufRef::try_from(buf).map_err(|e| FsError::Errno(e.errno()))?;
        self.raw_disk
            .write(number as BlockId, buf_ref)
            .map_err(|e| FsError::Errno(e.errno()))
    }

    pub fn flush(&mut self) -> FsResult {
        self.raw_disk.flush().map_err(|e| FsError::Errno(e.errno()))
    }

    pub fn size(&self) -> FsResult<usize> {
        Ok(self.size)
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
