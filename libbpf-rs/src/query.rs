//! Query the host about BPF
//!
//! For example, to list the name of every bpf program running on the system:
//! ```
//! use std::str::from_utf8;
//! use libbpf_rs::query::ProgInfoIter;
//!
//! let mut iter = ProgInfoIter::default();
//! for prog in iter {
//!     let converted_arr: Vec<u8> = prog.name
//!         .iter()
//!         .map(|x| *x as u8)
//!         .collect();
//!
//!     println!("{}", from_utf8(&converted_arr).unwrap());
//! }
//! ```

use core::ffi::c_void;
use std::mem::size_of;

use nix::{errno, unistd::close};

macro_rules! gen_info_impl {
    // This magic here allows us to embed doc comments into macro expansions
    ($(#[$attr:meta])*
     $name:ident, $info_ty:ty, $next_id:expr, $fd_by_id:expr) => {
        $(#[$attr])*
        #[derive(Default)]
        pub struct $name {
            cur_id: u32,
        }

        impl Iterator for $name {
            type Item = $info_ty;

            fn next(&mut self) -> Option<Self::Item> {
                if unsafe { $next_id(self.cur_id, &mut self.cur_id) } != 0 {
                    return None;
                }

                let fd = unsafe { $fd_by_id(self.cur_id) };
                if fd < 0 && errno::errno() == errno::Errno::ENOENT as i32 {
                    return None;
                }

                let mut item = <$info_ty>::default();
                let item_ptr: *mut $info_ty = &mut item;
                let mut len = size_of::<$info_ty>() as u32;

                let ret = unsafe { libbpf_sys::bpf_obj_get_info_by_fd(fd, item_ptr as *mut c_void, &mut len) };
                let _ = close(fd);
                if ret != 0 {
                    return None
                } else {
                    Some(item)
                }

            }
        }
    };
}

gen_info_impl!(
    /// Iterator that returns information about bpf programs currently running on the system.
    ProgInfoIter,
    libbpf_sys::bpf_prog_info,
    libbpf_sys::bpf_prog_get_next_id,
    libbpf_sys::bpf_prog_get_fd_by_id
);

gen_info_impl!(
    /// Iterator that returns information about bpf maps current created on the system.
    MapInfoIter,
    libbpf_sys::bpf_map_info,
    libbpf_sys::bpf_map_get_next_id,
    libbpf_sys::bpf_map_get_fd_by_id
);

gen_info_impl!(
    /// Iterator that returns information about system BTF.
    BtfInfoIter,
    libbpf_sys::bpf_btf_info,
    libbpf_sys::bpf_btf_get_next_id,
    libbpf_sys::bpf_btf_get_fd_by_id
);
