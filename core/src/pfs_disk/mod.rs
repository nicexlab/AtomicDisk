pub use self::open_options::OpenOptions;
use crate::layers::disk::bio::{BioReq, BioType};
use crate::os::Mutex;
use crate::os::SeekFrom;
use crate::pfs::fs::SgxFile as PfsFile;
use crate::pfs::sys::error::OsError;
use crate::{prelude::*, BlockSet, BufMut};
use crate::{BufRef, Errno};
use crate::os::{Aead, AeadIv as Iv, AeadKey as Key, AeadMac as Mac};
mod open_options;



struct BufMutVec<'a> {
    bufs: &'a mut [BufMut<'a>],
    nblocks: usize,
}

impl<'a> BufMutVec<'a> {
    pub fn from_bufs(bufs: &'a mut [BufMut<'a>]) -> Self {
        debug_assert!(bufs.len() > 0);
        let nblocks = bufs
            .iter()
            .map(|buf| buf.nblocks())
            .fold(0_usize, |sum, nblocks| sum.saturating_add(nblocks));
        Self { bufs, nblocks }
    }

    pub fn nblocks(&self) -> usize {
        self.nblocks
    }

    pub fn nth_buf_mut_slice(&mut self, mut nth: usize) -> &mut [u8] {
        debug_assert!(nth < self.nblocks);
        for buf in self.bufs.iter_mut() {
            let nblocks = buf.nblocks();
            if nth >= buf.nblocks() {
                nth -= nblocks;
            } else {
                return &mut buf.as_mut_slice()[nth * BLOCK_SIZE..(nth + 1) * BLOCK_SIZE];
            }
        }
        &mut []
    }
}


/// A virtual disk backed by a protected file of Intel SGX Protected File
/// System Library (SGX-PFS).
///
/// This type of disks is considered (relatively) secure.
pub struct PfsDisk<D: BlockSet> {
    file: Mutex<PfsFile<D>>,
    path: String,
    total_blocks: usize,
    can_read: bool,
    can_write: bool,
}

// Safety. PfsFile does not implement Send, but it is safe to do so.
unsafe impl<D: BlockSet> Send for PfsDisk<D> {}
// Safety. PfsFile does not implement Sync but it is safe to do so.
unsafe impl<D: BlockSet> Sync for PfsDisk<D> {}

// The first 3KB file data of PFS are stored in the metadata node. All remaining
// file data are stored in nodes of 4KB. We need to consider this internal
// offset so that our block I/O are aligned with the PFS internal node boundaries.
const PFS_INNER_OFFSET: usize = 3 * 1024;

impl<D: BlockSet> PfsDisk<D> {
    /// Open a disk backed by an existing PFS file on the host.
    pub fn open(disk: D, root_key: Key, path: Option<&str>) -> Result<Self> {
        let path = path.unwrap_or("pfsdisk");
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path, disk, root_key)
    }

    /// Open a disk by opening or creating a PFS file on the give path.
    pub fn create(disk: D, root_key: Key, path: Option<&str>) -> Result<Self> {
        let path = path.unwrap_or("pfsdisk");
        let total_blocks = PfsDisk::<D>::total_data_blocks(disk.nblocks());
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .total_blocks(total_blocks)
            .open(path, disk, root_key)
    }

    /// Returns the PFS file on the host Linux.
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn read(&self, addr: usize, mut buf: BufMut) -> Result<()> {
        if !self.can_read {
            return_errno_with_msg!(Errno::IoFailed, "read is not allowed")
        }
        self.validate_range(addr)?;

        let offset = addr * BLOCK_SIZE + PFS_INNER_OFFSET;
        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(offset as u64)).unwrap();
        file.read(buf.as_mut_slice()).unwrap();
        Ok(())
    }

    pub fn readv<'a>(&self,addr: usize, bufs: &'a mut [BufMut<'a>]) -> Result<()> {
        let mut buf_vec = BufMutVec::from_bufs(bufs);
        let nblocks = buf_vec.nblocks();

        for i in 0..nblocks {
            let buf = buf_vec.nth_buf_mut_slice(i);
            self.validate_range(addr)?;

            let offset = (addr + i) * BLOCK_SIZE + PFS_INNER_OFFSET;
            let mut file = self.file.lock();
            file.seek(SeekFrom::Start(offset as u64)).unwrap();
            file.read(buf).unwrap();
        }
        Ok(())
    }

    pub fn write(&self, addr: usize, buf: BufRef) -> Result<()> {
        if !self.can_write {
            return_errno_with_msg!(Errno::IoFailed, "write is not allowed")
        }
        self.validate_range(addr)?;
        let offset = addr * BLOCK_SIZE + PFS_INNER_OFFSET;
        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(offset as u64)).unwrap();
        file.write(buf.as_slice()).unwrap();
        Ok(())
    }

    pub fn writev(&self, mut addr: usize, bufs: &[BufRef]) -> Result<()> {
        for buf in bufs {
            self.write(addr, *buf)?;
            addr += buf.nblocks();
        }
        Ok(())
    }

    pub fn sync(&self) -> Result<()> {
        let mut file = self.file.lock();
        file.flush().map_err(|e| e.to_errno())
    }

    fn do_read(&self, req: &Arc<BioReq>) -> Result<()> {
        if !self.can_read {
            return_errno_with_msg!(Errno::IoFailed, "read is not allowed")
        }

        let (offset, _) = self.get_range_in_bytes(&req)?;
        let offset = offset + PFS_INNER_OFFSET;

        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(offset as u64)).unwrap();
        req.access_mut_bufs_with(|bufs| {
            // We do not use read_vectored. This is because PfsFile does not give
            // a specialized implementation that offers a performance advantage.
            for buf in bufs {
                let read_len = file.read(buf.as_mut_slice()).unwrap();
                debug_assert!(read_len == buf.len());
            }
        });
        drop(file);

        Ok(())
    }

    fn do_write(&self, req: &Arc<BioReq>) -> Result<()> {
        if !self.can_write {
            return_errno_with_msg!(Errno::IoFailed, "write is not allowed")
        }

        let (offset, _) = self.get_range_in_bytes(&req)?;
        let offset = offset + PFS_INNER_OFFSET;

        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(offset as u64)).unwrap();
        req.access_bufs_with(|bufs| {
            // We do not use read_vectored. This is because PfsFile does not give
            // a specialized implementation that offers a performance advantage.
            for buf in bufs {
                let write_len = file.write(buf.as_slice()).unwrap();
                debug_assert!(write_len == buf.len());
            }
        });
        drop(file);

        Ok(())
    }

    fn do_flush(&self) -> Result<()> {
        if !self.can_write {
            return_errno_with_msg!(Errno::IoFailed, "flush is not allowed")
        }

        let mut file = self.file.lock();
        let ret = file.flush().map_err(|e| e.to_errno());
        // TODO: sync
        //file.sync_data()?;
        drop(file);

        ret
    }

    fn validate_range(&self, addr: usize) -> Result<()> {
        if addr >= self.total_blocks {
            return_errno_with_msg!(Errno::IoFailed, "invalid block range")
        }
        Ok(())
    }

    fn get_range_in_bytes(&self, req: &Arc<BioReq>) -> Result<(usize, usize)> {
        let begin_block = req.addr();
        let end_block = begin_block + req.nblocks();
        if end_block > self.total_blocks {
            return_errno_with_msg!(Errno::IoFailed, "invalid block range")
        }
        let begin_offset = begin_block * BLOCK_SIZE;
        let end_offset = end_block * BLOCK_SIZE;
        Ok((begin_offset, end_offset))
    }
    fn total_data_blocks(total_blocks: usize) -> usize {
        total_blocks * 13 / 16
    }
}

// impl BlockDevice for PfsDisk {
//     fn total_blocks(&self) -> usize {
//         self.total_blocks
//     }

//     fn submit(&self, req: Arc<BioReq>) -> BioSubmission {
//         // Update the status of req to submittted
//         let submission = BioSubmission::new(req);

//         let req = submission.req();
//         let type_ = req.type_();
//         let res = match type_ {
//             BioType::Read => self.do_read(req),
//             BioType::Write => self.do_write(req),
//             BioType::Flush => self.do_flush(),
//         };

//         // Update the status of req to completed and set the response
//         let resp = res.map_err(|e| e.errno());
//         unsafe {
//             req.complete(resp);
//         }

//         submission
//     }

impl<D: BlockSet> Drop for PfsDisk<D> {
    fn drop(&mut self) {
        let mut file = self.file.lock();
        file.flush().unwrap();
        // TODO: sync
        // file.sync_all()?;
    }
}

impl<D: BlockSet> fmt::Debug for PfsDisk<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PfsDisk")
            .field("path", &self.path)
            .field("total_blocks", &self.total_blocks)
            .finish()
    }
}

mod test {
    use super::*;
    use crate::{
        layers::{
            bio::MemDisk,
            disk::bio::{BioReqBuilder, BlockBuf},
        },
        Buf,
    };
    use core::ptr::NonNull;
    use std::sync::Once;
    static INIT_LOG: Once = Once::new();
    pub fn init_logger() {
        INIT_LOG.call_once(|| {
            env_logger::builder()
                .is_test(true)
                .filter_level(log::LevelFilter::Debug)
                .try_init()
                .unwrap();
        });
    }

    #[test]
    fn test_read_write() {
        let root_key = Key::default();
        let disk = MemDisk::create(100).unwrap();
        let disk = PfsDisk::create(disk, root_key, None).unwrap();
        let data_buf = vec![1u8; BLOCK_SIZE];
        let buf = BufRef::try_from(data_buf.as_slice()).unwrap();
        disk.write(0, buf).unwrap();

        let mut read_buf = Buf::alloc(1).unwrap();
        disk.read(0, read_buf.as_mut()).unwrap();
        assert_eq!(read_buf.as_slice(), &[1u8; BLOCK_SIZE]);
    }

    #[test]
    fn multi_block_read_write() {
        init_logger();
        let root_key = Key::default();
        let disk = MemDisk::create(11000).unwrap();
        let disk = PfsDisk::create(disk, root_key, None).unwrap();

        let block_count = 8000;
        for i in 0..block_count {
            let data_buf = vec![i as u8; BLOCK_SIZE];
            let buf = BufRef::try_from(data_buf.as_slice()).unwrap();
            disk.write(i, buf).unwrap();
        }

        for i in 0..block_count {
            let mut read_buf = Buf::alloc(1).unwrap();
            disk.read(i, read_buf.as_mut()).unwrap();
            assert_eq!(read_buf.as_slice(), &[i as u8; BLOCK_SIZE]);
        }
    }
}
