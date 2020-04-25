use crate::*;

/// Represents an attached [`Program`].
///
/// This struct is used to model ownership. The underlying program will be detached
/// when this object is dropped if nothing else is holding a reference count.
pub struct Link {}

impl Link {
    /// Replace the underlying prog with `prog`.
    ///
    /// Returns the replaced [`Program`] on success.
    pub fn update_prog(&mut self, _prog: Program) -> Result<Program> {
        unimplemented!();
    }
}
