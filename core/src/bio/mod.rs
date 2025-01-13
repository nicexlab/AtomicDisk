pub mod block_buf;
pub mod bio_req;
pub mod block_ring;
pub mod block_set;
pub mod block_log;

pub const BLOCK_SIZE: usize = 4096;

pub type BlockId = usize;
pub use block_buf::{Buf, BufMut, BufRef};
pub use block_set::BlockSet;
pub use block_log::BlockLog;
pub use block_set::MemDisk;

