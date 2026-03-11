//! Pipes — Inter-Process Communication
//!
//! Provides an in-kernel pipe mechanism for data transfer between threads/processes.
//! Used for shell pipelines and general IPC.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Pipe buffer size (4 KiB).
const PIPE_BUF_SIZE: usize = 4096;

/// Next pipe ID.
static NEXT_PIPE_ID: AtomicU64 = AtomicU64::new(1);

/// A kernel pipe — a bounded ring buffer.
pub struct Pipe {
    pub id: u64,
    buffer: [u8; PIPE_BUF_SIZE],
    read_pos: usize,
    write_pos: usize,
    count: usize,
    /// Number of open write ends. When 0, reads past end return EOF.
    writers: u32,
    /// Number of open read ends.
    readers: u32,
    closed: bool,
}

impl Pipe {
    fn new(id: u64) -> Self {
        Self {
            id,
            buffer: [0; PIPE_BUF_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
            writers: 1,
            readers: 1,
            closed: false,
        }
    }

    /// Read up to `buf.len()` bytes from the pipe. Returns bytes read.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.count);
        for i in 0..to_read {
            buf[i] = self.buffer[self.read_pos];
            self.read_pos = (self.read_pos + 1) % PIPE_BUF_SIZE;
        }
        self.count -= to_read;
        to_read
    }

    /// Write up to `data.len()` bytes into the pipe. Returns bytes written.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let space = PIPE_BUF_SIZE - self.count;
        let to_write = data.len().min(space);
        for i in 0..to_write {
            self.buffer[self.write_pos] = data[i];
            self.write_pos = (self.write_pos + 1) % PIPE_BUF_SIZE;
        }
        self.count += to_write;
        to_write
    }

    /// Check if the pipe has data available to read.
    pub fn has_data(&self) -> bool {
        self.count > 0
    }

    /// Check if write end is closed (EOF for readers).
    pub fn is_eof(&self) -> bool {
        self.writers == 0 && self.count == 0
    }

    pub fn available(&self) -> usize {
        self.count
    }
}

/// Global pipe table.
static PIPE_TABLE: Mutex<Vec<Pipe>> = Mutex::new(Vec::new());

/// Create a new pipe. Returns the pipe ID.
pub fn create_pipe() -> u64 {
    let id = NEXT_PIPE_ID.fetch_add(1, Ordering::Relaxed);
    PIPE_TABLE.lock().push(Pipe::new(id));
    id
}

/// Read from a pipe by ID.
pub fn pipe_read(pipe_id: u64, buf: &mut [u8]) -> Option<usize> {
    let mut pipes = PIPE_TABLE.lock();
    let pipe = pipes.iter_mut().find(|p| p.id == pipe_id)?;
    Some(pipe.read(buf))
}

/// Write to a pipe by ID.
pub fn pipe_write(pipe_id: u64, data: &[u8]) -> Option<usize> {
    let mut pipes = PIPE_TABLE.lock();
    let pipe = pipes.iter_mut().find(|p| p.id == pipe_id)?;
    Some(pipe.write(data))
}

/// Increment the writer count (e.g. when a second fd aliases the write-end).
pub fn pipe_add_writer(pipe_id: u64) {
    let mut pipes = PIPE_TABLE.lock();
    if let Some(pipe) = pipes.iter_mut().find(|p| p.id == pipe_id) {
        pipe.writers = pipe.writers.saturating_add(1);
    }
}

/// Close the write end of a pipe.
pub fn pipe_close_writer(pipe_id: u64) {
    let mut pipes = PIPE_TABLE.lock();
    if let Some(pipe) = pipes.iter_mut().find(|p| p.id == pipe_id) {
        pipe.writers = pipe.writers.saturating_sub(1);
    }
}

/// Close the read end of a pipe.
pub fn pipe_close_reader(pipe_id: u64) {
    let mut pipes = PIPE_TABLE.lock();
    if let Some(pipe) = pipes.iter_mut().find(|p| p.id == pipe_id) {
        pipe.readers = pipe.readers.saturating_sub(1);
    }
    // Clean up pipes with no readers and no writers.
    pipes.retain(|p| p.readers > 0 || p.writers > 0);
}

/// Check if a pipe has data.
pub fn pipe_has_data(pipe_id: u64) -> bool {
    let pipes = PIPE_TABLE.lock();
    pipes.iter().find(|p| p.id == pipe_id)
        .map(|p| p.has_data())
        .unwrap_or(false)
}

/// Check if a pipe's write end is closed.
pub fn pipe_is_eof(pipe_id: u64) -> bool {
    let pipes = PIPE_TABLE.lock();
    pipes.iter().find(|p| p.id == pipe_id)
        .map(|p| p.is_eof())
        .unwrap_or(true)
}
