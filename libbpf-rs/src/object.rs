use std::path::Path;

use crate::*;

pub struct Object {}

impl Object {
    pub fn with_path<P: AsRef<Path>>(_path: P) -> Result<Self> {
        unimplemented!();
    }
}
