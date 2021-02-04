//! Parse BPF Type Format (BTF)
//!
//! This module parses BTF information.
//!
//! For example, to list the name of all structs captured by BTF and their sizes:
//! ```no_run
//! # use libbpf_rs::btf::{Btf, BtfType};
//! # fn main() -> libbpf_rs::Result<()> {
//! # let object_file = vec![0; 128];
//! let btf = Btf::new("myobj", &object_file)?.expect("BTF not found");
//! for ty in btf.types() {
//!     match ty {
//!         BtfType::Struct(s) => println!("{} is {}B", s.name, s.size),
//!         _ => (),
//!     }
//! }
//!
//! # Ok(())
//! # }
//! ```

#[allow(clippy::module_inception)]
mod btf;
mod c_types;
mod types;

pub use btf::Btf;
pub use types::*;
