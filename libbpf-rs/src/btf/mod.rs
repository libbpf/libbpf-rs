//! Parse and introspect btf information, from files or loaded objects.
//!
//! To find a specific type you can use one of 3 methods
//!
//! - [Btf::type_by_name]
//! - [Btf::type_by_id]
//! - [Btf::type_by_kind]
//!
//! All of these are generic over `K`, which is any type that can be created from a [`BtfType`],
//! for all of these methods, not finding any type by the passed parameter or finding a type of
//! another [`BtfKind`] will result in a [`None`] being returned (or filtered out in the case of
//! [`Btf::type_by_kind`]). If you want to get a type independently of the kind, just make sure `K`
//! binds to [`BtfType`].

use std::ffi::CStr;
use std::ffi::CString;
use std::marker::PhantomData;
use std::mem::size_of;
use std::os::raw::c_void;
use std::os::unix::prelude::AsRawFd;
use std::os::unix::prelude::FromRawFd;
use std::os::unix::prelude::OsStrExt;
use std::os::unix::prelude::OwnedFd;
use std::path::Path;
use std::ptr::NonNull;

use crate::libbpf_sys;
use crate::util::create_bpf_entity_checked;
use crate::util::create_bpf_entity_checked_opt;
use crate::util::parse_ret_i32;
use crate::Error;
use crate::Result;

/// The btf information of a bpf object.
///
/// The lifetime bound protects against this object outliving its source. This can happen when it
/// was derived from an [`Object`](super::Object), which owns the data this structs points too. When
/// instead the [`Btf::from_path`] method is used, the lifetime will be `'static` since it doesn't
/// borrow from anything.
#[derive(Debug)]
pub struct Btf<'source> {
    ptr: NonNull<libbpf_sys::btf>,
    needs_drop: bool,
    _marker: PhantomData<&'source ()>,
}

impl Btf<'static> {
    /// Load the btf information from an ELF file.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = {
            let mut v = path.as_ref().as_os_str().as_bytes().to_vec();
            v.push(0);
            CString::from_vec_with_nul(v).map_err(|_| {
                Error::InvalidInput(format!("invalid path {:?}, has null bytes", path.as_ref()))
            })?
        };
        let ptr = create_bpf_entity_checked(|| unsafe {
            libbpf_sys::btf__parse_elf(path.as_ptr(), std::ptr::null_mut())
        })?;
        Ok(Self {
            ptr,
            needs_drop: true,
            _marker: PhantomData,
        })
    }

    /// Load the btf information of an bpf object from a program id.
    pub fn from_prog_id(id: u32) -> Result<Self> {
        let fd = parse_ret_i32(unsafe { libbpf_sys::bpf_prog_get_fd_by_id(id) })?;
        let fd = unsafe {
            // SAFETY: parse_ret_i32 will check that this fd is above -1
            OwnedFd::from_raw_fd(fd)
        };
        let mut info = libbpf_sys::bpf_prog_info::default();
        parse_ret_i32(unsafe {
            libbpf_sys::bpf_obj_get_info_by_fd(
                fd.as_raw_fd(),
                (&mut info as *mut libbpf_sys::bpf_prog_info).cast::<c_void>(),
                &mut (size_of::<libbpf_sys::bpf_prog_info>() as u32),
            )
        })?;

        let ptr = create_bpf_entity_checked(|| unsafe {
            libbpf_sys::btf__load_from_kernel_by_id(info.btf_id)
        })?;

        Ok(Self {
            ptr,
            needs_drop: true,
            _marker: PhantomData,
        })
    }
}

impl<'btf> Btf<'btf> {
    pub(crate) fn from_bpf_object(obj: &'btf libbpf_sys::bpf_object) -> Result<Self> {
        let ptr = create_bpf_entity_checked_opt(|| unsafe {
            // SAFETY: the obj pointer is valid since it's behind a reference.
            libbpf_sys::bpf_object__btf(obj)
        })?
        .ok_or_else(|| Error::Internal("btf not found".into()))?;
        Ok(Self {
            ptr,
            needs_drop: false,
            _marker: PhantomData,
        })
    }

    /// Gets a string at a given offset.
    ///
    /// Returns `None` when the offset is out of bounds.
    fn name_at(&self, offset: u32) -> Option<&CStr> {
        let name = unsafe {
            // SAFETY:
            // Assuming that btf is a valid pointer, this is always okay to call.
            libbpf_sys::btf__name_by_offset(self.ptr.as_ptr(), offset)
        };
        NonNull::new(name as *mut i8)
            .map(|p| unsafe {
                // SAFETY: a non-null pointer comming from libbpf is always valid
                CStr::from_ptr(p.as_ptr())
            })
            .filter(|s| s.to_bytes().is_empty()) // treat empty strings as none
    }

    /// Whether this btf instance has no types.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The number of [BtfType]s in this object.
    pub fn len(&self) -> usize {
        unsafe {
            // SAFETY: the btf pointer is valid.
            libbpf_sys::btf__type_cnt(self.ptr.as_ptr()) as usize
        }
    }
}

impl Drop for Btf<'_> {
    fn drop(&mut self) {
        if self.needs_drop {
            unsafe {
                // SAFETY: the btf pointer is valid.
                libbpf_sys::btf__free(self.ptr.as_ptr())
            }
        }
    }
}
