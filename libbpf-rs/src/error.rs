use std::io;
use std::result;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] io::Error),
    #[error("System error, errno: {0}")]
    System(u32),
    #[error("Invalid binary: {0}")]
    InvalidObjectFile(String),
    #[error("Invalid map: {0}")]
    InvalidMap(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = result::Result<T, Error>;
