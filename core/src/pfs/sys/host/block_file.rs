use super::HostFs;
use crate::{
    bail, ensure,
    pfs::sys::node::NODE_SIZE,
    BlockId, BlockSet, BufMut, BufRef, Errno, Error,
};
use crate::prelude::*;

#[derive(Debug)]
pub struct BlockFile<D> {
    raw_disk: D,
    size: usize,
}

impl<D: BlockSet> BlockFile<D> {
    pub fn create(raw_disk: D) -> Self {
        #[cfg(not(feature = "linux"))]
        info!("created host file, range [{}, {})", 0, raw_disk.nblocks());
        let size = raw_disk.nblocks() * NODE_SIZE;
        Self { raw_disk, size }
    }
    pub fn read(&mut self, number: u64, buf: &mut [u8]) -> Result<()> {
        ensure!(
            buf.len() == NODE_SIZE,
            Error::with_msg(
                Errno::NotBlockSizeAligned,
                "read buffer size not aligned to block size",
            )
        );
        let buf_mut = BufMut::try_from(buf)?;
        self.raw_disk
            .read(number as BlockId, buf_mut)?;
        Ok(())
    }

    pub fn write(&mut self, number: u64, buf: &[u8]) -> Result<()> {
        ensure!(
            buf.len() == NODE_SIZE,
            Error::with_msg(
                Errno::NotBlockSizeAligned,
                "write buffer size not aligned to block size",
            )
        );
        let block_end = (number as usize + 1) * NODE_SIZE;
        self.size = block_end.max(self.size);

        let buf_ref = BufRef::try_from(buf)?;
        self.raw_disk
            .write(number as BlockId, buf_ref)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.raw_disk.flush()?;
        Ok(())
    }

    pub fn size(&self) -> usize {
        self.raw_disk.nblocks() * NODE_SIZE
    }
}

impl<D: BlockSet> HostFs for BlockFile<D> {
    fn read(&mut self, number: u64, node: &mut dyn AsMut<[u8]>) -> Result<()> {
        self.read(number, node.as_mut())
    }

    fn write(&mut self, number: u64, node: &dyn AsRef<[u8]>) -> Result<()> {
        self.write(number, node.as_ref())
    }

    fn flush(&mut self) -> Result<()> {
        self.flush()
    }
}

// pub struct RecoveryFile<D> {
//     log: RawLog<D>,
// }

// impl<D: BlockSet> RecoveryFile<D> {
//     pub fn new(log: RawLog<D>) -> Self {
//         Self { log }
//     }
// }
