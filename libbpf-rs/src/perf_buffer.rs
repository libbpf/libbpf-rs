use std::time::Duration;

use crate::*;

/// Builds [`PerfBuffer`] instances
pub struct PerfBufferBuilder {}

impl PerfBufferBuilder {
    pub fn new(_map: Map) -> Self {
        unimplemented!();
    }

    /// Callback to run when a sample is received.
    ///
    /// This callback provides a raw byte slice. You may find libraries such as
    /// [`plain`](https://crates.io/crates/plain) helpful.
    ///
    /// Callback arguments are: (cpu, data).
    pub fn set_sample_cb<F>(&mut self, _cb: F) -> &mut Self
    where
        F: FnMut(u32, &[u8]),
    {
        unimplemented!();
    }

    /// Callback to run when a sample is received.
    ///
    /// Callback arguments are: (cpu, lost_count).
    pub fn set_lost_cb<F>(&mut self, _cb: F) -> &mut Self
    where
        F: FnMut(u32, u64),
    {
        unimplemented!();
    }

    /// The number of pages to size the ring buffer.
    pub fn set_pages(&mut self, _pages: usize) -> &mut Self {
        unimplemented!();
    }

    pub fn build(&mut self) -> Result<PerfBuffer> {
        unimplemented!();
    }
}

/// Represents a special kind of [`Map`]. Typically used to transfer data between
/// [`Program`]s and userspace.
pub struct PerfBuffer {}

impl PerfBuffer {
    pub fn poll(&mut self, _timeout: Duration) -> Result<()> {
        unimplemented!();
    }
}
