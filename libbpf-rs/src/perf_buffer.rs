use std::time::Duration;

use crate::*;

pub struct PerfBuffer {}

impl PerfBuffer {
    pub fn new(_map: Map, _pages: usize, _opts: PerfBufferOpts) -> Self {
        unimplemented!();
    }

    pub fn poll(&mut self, _timeout: Duration) {
        unimplemented!();
    }
}

#[derive(Default)]
pub struct PerfBufferOpts {}

impl PerfBufferOpts {
    pub fn new() -> Self {
        unimplemented!();
    }

    /// Callback to run when a sample is received.
    ///
    /// Callback arguments are: (ctx, cpu, data).
    pub fn sample_cb<F>(self, _cb: F) -> Self
    where
        F: FnMut(usize, u32, &[u8]),
    {
        unimplemented!();
    }

    /// Callback to run when a sample is received.
    ///
    /// Callback arguments are: (ctx, cpu, lost_count).
    pub fn lost_cb<F>(self, _cb: F) -> Self
    where
        F: FnMut(usize, u32, u64),
    {
        unimplemented!();
    }
}
