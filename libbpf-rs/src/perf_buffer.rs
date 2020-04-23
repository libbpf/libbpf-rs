use std::time::Duration;

use crate::*;

/// Represents a special kind of [`Map`]. Typically used to transfer data between
/// [`Program`]s and userspace.
pub struct PerfBuffer {}

impl PerfBuffer {
    pub fn new(_map: Map) -> Self {
        unimplemented!();
    }

    /// Callback to run when a sample is received.
    ///
    /// This callback provides a raw byte slice. You may find libraries such as
    /// [`plain`](https://crates.io/crates/plain) helpful.
    ///
    /// Callback arguments are: (cpu, data).
    pub fn sample_cb<F>(&mut self, _cb: F) -> &mut Self
    where
        F: FnMut(u32, &[u8]),
    {
        unimplemented!();
    }

    /// Callback to run when a sample is received.
    ///
    /// Callback arguments are: (cpu, lost_count).
    pub fn lost_cb<F>(&mut self, _cb: F) -> &mut Self
    where
        F: FnMut(u32, u64),
    {
        unimplemented!();
    }

    /// The number of pages to size the ring buffer.
    pub fn pages(&mut self, _pages: usize) -> &mut Self {
        unimplemented!();
    }

    pub fn poll(&mut self, _timeout: Duration) {
        unimplemented!();
    }
}
