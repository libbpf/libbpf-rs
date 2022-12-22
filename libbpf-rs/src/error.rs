use std::result;

use thiserror::Error;

/// Canonical error type for this crate.
#[derive(Error, Debug)]
pub enum Error {
    /// A system error occurred.
    #[error("System error, errno: {0}")]
    System(i32),
    /// An input was invalid.
    #[error("Input input: {0}")]
    InvalidInput(String),
    /// An internal error occurred.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// The result type used by this library, defaulting to [`Error`][crate::Error]
/// as the error type.
pub type Result<T> = result::Result<T, Error>;
