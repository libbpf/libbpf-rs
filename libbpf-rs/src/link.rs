use crate::object::{Object, Program};
use crate::*;

pub struct Link {}

impl Link {
    /// Attach a `Program` to the system. The attach point is determined by looking
    /// at which section the `Program` is assigned to.
    pub fn attach(_prog: Program) -> Result<Self> {
        unimplemented!();
    }

    /// Convenience function to [`Link::attach`] all [`Program`]s in an [`Object`].
    ///
    /// Note that this excludes [perf events](https://linux.die.net/man/2/perf_event_open)
    /// because libbpf does not have enough information to construct an event.
    pub fn attach_all(_obj: Object) -> Result<Vec<Self>> {
        unimplemented!();
    }

    /// Attach a [`Program`] to a
    /// [perf_event_open()](https://linux.die.net/man/2/perf_event_open)
    /// file descriptor.
    pub fn attach_perf_event(_prog: Program, _pfd: i64) -> Result<Self> {
        unimplemented!();
    }

    /// Replace the underlying [`Program`] with another prog.
    pub fn update_prog(&mut self, _prog: Program) -> Result<()> {
        unimplemented!();
    }
}
