pub use self::open_options::OpenOptions;
use crate::layers::disk::bio::{BioReq, BioType};
use crate::os::Mutex;
use crate::pfs::fs::SgxFile as PfsFile;
use crate::pfs::sys::error::OsError;
use crate::{prelude::*, BlockSet, BufMut};
use crate::{BufRef, Errno};
use std::fmt;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};

mod open_options;

/// A virtual disk backed by a protected file of Intel SGX Protected File
/// System Library (SGX-PFS).
///
/// This type of disks is considered (relatively) secure.
pub struct PfsDisk<D: BlockSet> {
    file: Mutex<PfsFile<D>>,
    path: PathBuf,
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
    pub fn open<P: AsRef<Path>>(path: P, disk: D) -> Result<Self> {
        OpenOptions::new().read(true).write(true).open(path, disk)
    }

    /// Open a disk by opening or creating a PFS file on the give path.
    pub fn create<P: AsRef<Path>>(path: P, total_blocks: usize, disk: D) -> Result<Self> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .total_blocks(total_blocks)
            .open(path, disk)
    }

    /// Returns the PFS file on the host Linux.
    pub fn path(&self) -> &Path {
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
        let ret = file.flush().map_err(|e| e.raw_os_error().unwrap().into());
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

    #[test]
    fn test_read_write() {
        let disk = MemDisk::create(100).unwrap();
        let disk = PfsDisk::create("test.data", 100, disk).unwrap();
        let data_buf = vec![1u8; BLOCK_SIZE];
        let buf = BufRef::try_from(data_buf.as_slice()).unwrap();
        disk.write(0, buf).unwrap();

        let mut read_buf = Buf::alloc(1).unwrap();
        disk.read(0, read_buf.as_mut()).unwrap();
        assert_eq!(read_buf.as_slice(), &[1u8; BLOCK_SIZE]);
        std::fs::remove_file("test.data").unwrap();
    }

    #[test]
    fn multi_block_read_write() {
        let disk = MemDisk::create(10100).unwrap();
        let disk = PfsDisk::create("test.disk", 10100, disk).unwrap();

        let block_count = 10000;
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
        std::fs::remove_file("test.disk").unwrap();
    }
}
