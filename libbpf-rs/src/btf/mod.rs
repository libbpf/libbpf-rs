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
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::Deref;
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
use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;

/// The various btf types.
#[derive(IntoPrimitive, TryFromPrimitive, Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum BtfKind {
    /// [Void](types::Void)
    Void = 0,
    /// [Int](types::Int)
    Int,
    /// [Ptr](types::Ptr)
    Ptr,
    /// [Array](types::Array)
    Array,
    /// [Struct](types::Struct)
    Struct,
    /// [Union](types::Union)
    Union,
    /// [Enum](types::Enum)
    Enum,
    /// [Fwd](types::Fwd)
    Fwd,
    /// [Typedef](types::Typedef)
    Typedef,
    /// [Volatile](types::Volatile)
    Volatile,
    /// [Const](types::Const)
    Const,
    /// [Restrict](types::Restrict)
    Restrict,
    /// [Func](types::Func)
    Func,
    /// [FuncProto](types::FuncProto)
    FuncProto,
    /// [Var](types::Var)
    Var,
    /// [DataSec](types::DataSec)
    DataSec,
    /// [Float](types::Float)
    Float,
    /// [DeclTag](types::DeclTag)
    DeclTag,
    /// [TypeTag](types::TypeTag)
    TypeTag,
    /// [Enum64](types::Enum64)
    Enum64,
}

/// The id of a btf type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId(u32);

impl From<u32> for TypeId {
    fn from(s: u32) -> Self {
        Self(s)
    }
}

impl From<TypeId> for u32 {
    fn from(t: TypeId) -> Self {
        t.0
    }
}

impl Display for TypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
    /// Returns [`None`] when the offset is out of bounds or if the name is empty.
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
            .filter(|s| !s.to_bytes().is_empty()) // treat empty strings as none
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

    /// Find a btf type by name
    ///
    /// # Panics
    /// If `name` has null bytes.
    pub fn type_by_name<'s, K>(&'s self, name: &str) -> Option<K>
    where
        K: TryFrom<BtfType<'s>>,
    {
        let c_string = CString::new(name)
            .map_err(|_| Error::InvalidInput(format!("{name:?} contains null bytes")))
            .unwrap();
        let ty = unsafe {
            // SAFETY: the btf pointer is valid and the c_string pointer was created from safe code
            // therefore it's also valid.
            libbpf_sys::btf__find_by_name(self.ptr.as_ptr(), c_string.as_ptr())
        };
        if ty < 0 {
            None
        } else {
            self.type_by_id(TypeId(ty as _))
        }
    }

    /// Find a type by it's [TypeId].
    pub fn type_by_id<'s, K>(&'s self, type_id: TypeId) -> Option<K>
    where
        K: TryFrom<BtfType<'s>>,
    {
        let btf_type = unsafe {
            // SAFETY: the btf pointer is valid.
            libbpf_sys::btf__type_by_id(self.ptr.as_ptr(), type_id.0)
        };

        let btf_type = NonNull::new(btf_type as *mut libbpf_sys::btf_type)?;

        let ty = unsafe {
            // SAFETY: if it is non-null then it points to a valid type.
            btf_type.as_ref()
        };

        let name = self.name_at(ty.name_off);

        BtfType {
            type_id,
            name,
            source: self,
            ty,
        }
        .try_into()
        .ok()
    }

    /// Find all types of a specific type kind.
    pub fn type_by_kind<'s, K>(&'s self) -> impl Iterator<Item = K> + 's
    where
        K: TryFrom<BtfType<'s>>,
    {
        (1..self.len() as u32)
            .map(TypeId::from)
            .filter_map(|id| self.type_by_id(id))
            .filter_map(|t| K::try_from(t).ok())
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

/// An undiscriminated btf type
#[derive(Clone, Copy)]
pub struct BtfType<'btf> {
    type_id: TypeId,
    name: Option<&'btf CStr>,
    source: &'btf Btf<'btf>,
    ///  the __bindgen_anon_1 field is a union defined as
    ///  ```no_run
    ///  union btf_type__bindgen_ty_1 {
    ///      size_: u32,
    ///      type_: u32,
    ///  }
    ///  ```
    ///
    ty: &'btf libbpf_sys::btf_type,
}

impl Debug for BtfType<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BtfType")
            .field("type_id", &self.type_id)
            .field("name", &self.name())
            .field("source", &self.source)
            .field("ty", &(self.ty as *const _))
            .finish()
    }
}

impl<'btf> BtfType<'btf> {
    /// This type's type id.
    #[inline]
    pub fn type_id(&self) -> TypeId {
        self.type_id
    }

    /// This type's name.
    #[inline]
    pub fn name(&'_ self) -> Option<&'btf CStr> {
        self.name
    }

    /// This type's kind.
    #[inline]
    pub fn kind(&self) -> BtfKind {
        ((self.ty.info >> 24) & 0x1f).try_into().unwrap()
    }

    #[inline]
    fn vlen(&self) -> u32 {
        self.ty.info & 0xffff
    }

    #[inline]
    fn kind_flag(&self) -> bool {
        (self.ty.info >> 31) == 1
    }

    /// Whether this represent's a modifier.
    #[inline]
    pub fn is_mod(&self) -> bool {
        matches!(
            self.kind(),
            BtfKind::Volatile | BtfKind::Const | BtfKind::Restrict | BtfKind::TypeTag
        )
    }

    /// Whether this represents any kind of enum.
    #[inline]
    pub fn is_any_enum(&self) -> bool {
        matches!(self.kind(), BtfKind::Enum | BtfKind::Enum64)
    }

    /// Whether this btf type is core compatible to `other`.
    #[inline]
    pub fn is_core_compat(&self, other: &Self) -> bool {
        self.kind() == other.kind() || (self.is_any_enum() && other.is_any_enum())
    }

    /// Whether this type represents a composite type (struct/union).
    #[inline]
    pub fn is_composite(&self) -> bool {
        matches!(self.kind(), BtfKind::Struct | BtfKind::Union)
    }
}

/// Some btf types have a size field, describing their size.
///
/// # Safety
///
/// It's only safe to implement this for types where the underlying btf_type has a .size set.
///
/// See the [docs](https://www.kernel.org/doc/html/latest/bpf/btf.html) for a reference of which
/// [`BtfKind`] can implement this trait.
pub unsafe trait HasSize<'btf>: Deref<Target = BtfType<'btf>> + sealed::Sealed {
    /// The size of the described type.
    #[inline]
    fn size(&self) -> usize {
        (unsafe { self.ty.__bindgen_anon_1.size }) as usize
    }
}

/// Some btf types refer to other types by their type id.
///
/// # Safety
///
/// It's only safe to implement this for types where the underlying btf_type has a .type set.
///
/// See the [docs](https://www.kernel.org/doc/html/latest/bpf/btf.html) for a reference of which
/// [`BtfKind`] can implement this trait.
pub unsafe trait ReferencesType<'btf>:
    Deref<Target = BtfType<'btf>> + sealed::Sealed
{
    /// The referenced type's id.
    #[inline]
    fn referenced_type_id(&self) -> TypeId {
        TypeId(unsafe { self.ty.__bindgen_anon_1.type_ })
    }
}

mod sealed {
    pub trait Sealed {}
}
