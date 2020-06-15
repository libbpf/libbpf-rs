use std::result;

use thiserror::Error;

/// Canonical error type for this crate.
#[derive(Error, Debug)]
pub enum Error {
    #[error("System error, errno: {0}")]
    System(i32),
    #[error("Input input: {0}")]
    InvalidInput(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = result::Result<T, Error>;
