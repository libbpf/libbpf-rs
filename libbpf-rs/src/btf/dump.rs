//! Dump btf information.

use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io;
use std::mem;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::ptr::NonNull;
use std::result;

use crate::btf::Btf;
use crate::btf::TypeId;
use crate::object::AsRawLibbpf;
use crate::util;
use crate::util::parse_ret_i32;
use crate::util::validate_bpf_ret;
use crate::Error;
use crate::ErrorExt as _;
use crate::Result;

struct CbStruct<'btf> {
    write_cb: Box<dyn io::Write + 'btf>,
    result: Option<result::Result<(), io::Error>>,
}

impl Debug for CbStruct<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self { write_cb, result } = self;
        f.debug_struct("CbStruct")
            .field("write_cb", &(write_cb as *const _))
            .field("result", &result)
            .finish()
    }
}

struct DropGuard<T> {
    inner: Option<NonNull<T>>,
}

impl<T> DropGuard<T> {
    fn new(inner: NonNull<T>) -> Self {
        Self { inner: Some(inner) }
    }

    fn as_ref(&self) -> &NonNull<T> {
        self.inner.as_ref().unwrap()
    }

    fn into_inner(mut self) -> NonNull<T> {
        self.inner.take().unwrap()
    }
}

impl<T> Drop for DropGuard<T> {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            drop(unsafe { Box::from_raw(inner.as_ptr()) })
        }
    }
}

unsafe extern "C" fn call_write_cb(
    ctx: *mut c_void,
    fmtstr: *const c_char,
    // bindgen generated va_list type varies on different platforms, so just use void pointer
    // instead. It's safe because this argument is always a pointer.
    // The pointer of this function would be transmuted and passing to BtfDump::new below.
    // See <https://github.com/rust-lang/rust-bindgen/issues/2631>
    va_list: *mut c_void,
) {
    let callback_struct = ctx.cast::<CbStruct<'_>>();

    let result = unsafe { &(*callback_struct).result };
    if !matches!(result, Some(Err(_))) {
        let cb = unsafe { &mut (*callback_struct).write_cb };
        let result = unsafe { vsprintf::vsprintf_raw(fmtstr, va_list) }
            .and_then(|bytes| cb.write_all(&bytes));
        unsafe { (*callback_struct).result = Some(result) };
    }
}

/// Options to optionally be provided when emitting type declaration.
#[derive(Clone, Debug, Default)]
#[doc(alias = "btf_dump_emit_type_decl_opts")]
pub struct EmitTypeDeclOpts {
    /// Optional field name for type declaration.
    pub field_name: Option<String>,
    /// Extra indentation level, in number of tabs, to emit for
    /// multi-line type declarations.
    pub indent_level: usize,
    /// Strip all the const/volatile/restrict modifiers
    pub strip_mods: bool,
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

/// Dump btf information as in a compilable C syntax.
///
/// To dump a btf type, you can call [`BtfDump::dump_type`] with a
/// [`TypeId`]. It will emit all dependent types not yet emitted,
/// i.e., each type is emitted at most once per [`BtfDump`].
#[doc(alias = "btf_dump")]
#[derive(Debug)]
pub struct BtfDump<'btf> {
    ptr: NonNull<libbpf_sys::btf_dump>,
    callback_struct: NonNull<CbStruct<'btf>>,
    btf: &'btf Btf<'btf>,
}

impl Drop for BtfDump<'_> {
    #[doc(alias = "btf_dump__free")]
    fn drop(&mut self) {
        unsafe {
            libbpf_sys::btf_dump__free(self.ptr.as_ptr());
        }
        drop(unsafe { Box::from_raw(self.callback_struct.as_ptr()) })
    }
}

impl<'btf> BtfDump<'btf> {
    /// Create a new btf dump.
    #[doc(alias = "btf_dump__new")]
    pub fn new<F>(btf: &'btf Btf, write_cb: F) -> Result<Self>
    where
        F: io::Write + Sized + 'btf,
    {
        let opts = libbpf_sys::btf_dump_opts {
            sz: size_of::<libbpf_sys::btf_dump_opts>() as _,
        };

        // # Safety
        // call_write_cb has the same function signature as btf_dump_print_fn_t
        #[expect(clippy::missing_transmute_annotations)]
        let real_call_write_cb: libbpf_sys::btf_dump_printf_fn_t =
            unsafe { Some(mem::transmute(call_write_cb as *const ())) };

        let callback_struct = Box::into_raw(Box::new(CbStruct {
            write_cb: Box::new(write_cb),
            result: None,
        }));
        let callback_struct = unsafe { NonNull::new_unchecked(callback_struct) };
        let guard = DropGuard::new(callback_struct);

        let ptr = unsafe {
            libbpf_sys::btf_dump__new(
                btf.as_libbpf_object().as_ptr(),
                real_call_write_cb,
                guard.as_ref().as_ptr().cast(),
                &opts,
            )
        };

        let ptr = validate_bpf_ret(ptr).context("failed to create BTF dump")?;

        Ok(Self {
            ptr,
            callback_struct: guard.into_inner(),
            btf,
        })
    }

    fn map_callback_result(&mut self) -> Result<()> {
        unsafe {
            self.callback_struct
                .as_mut()
                .result
                .take()
                .unwrap_or(Ok(()))
                .map_err(Into::into)
        }
    }

    /// Dump a btf type, including all the necessary dependent types,
    /// given by [`TypeId`].
    #[doc(alias = "btf_dump__dump_type")]
    pub fn dump_type(&mut self, type_id: TypeId) -> Result<()> {
        parse_ret_i32(unsafe {
            libbpf_sys::btf_dump__dump_type(self.ptr.as_ptr(), type_id.into())
        })?;
        self.map_callback_result()
    }

    /// Emit a type declaration (e.g., field type declaration in a
    /// struct or argument declaration in function prototype) for a
    /// given [`TypeId`].
    #[doc(alias = "btf_dump__emit_type_decl")]
    pub fn emit_type_decl(&mut self, type_id: TypeId, opts: EmitTypeDeclOpts) -> Result<()> {
        // Unlike btf_dump__dump_type, btf_dump__emit_type_decl
        // currently doesn't validate type id, so check it here.
        // See https://github.com/libbpf/libbpf/blob/f5dcbae736e5d7f83a35718e01be1a8e3010fa39/src/btf_dump.c#L1300-L1320
        if u32::from(type_id) >= self.btf.len() as u32 {
            return Err(Error::with_invalid_data(format!(
                "out of range type id: {type_id}"
            )));
        }

        let EmitTypeDeclOpts {
            field_name,
            indent_level,
            strip_mods,
            _non_exhaustive,
        } = opts;

        let field_name = field_name
            .as_deref()
            .map(util::str_to_cstring)
            .transpose()?;
        let field_name_ptr = field_name.as_deref().unwrap_or(c"").as_ptr();

        #[allow(clippy::needless_update)]
        let libbpf_opts = libbpf_sys::btf_dump_emit_type_decl_opts {
            sz: size_of::<libbpf_sys::btf_dump_emit_type_decl_opts>() as _,
            field_name: field_name_ptr.cast(),
            indent_level: indent_level as c_int,
            strip_mods,
            // btf_dump_emit_type_decl_opts might have padding fields on some platform
            ..Default::default()
        };
        parse_ret_i32(unsafe {
            libbpf_sys::btf_dump__emit_type_decl(self.ptr.as_ptr(), type_id.into(), &libbpf_opts)
        })?;
        self.map_callback_result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btf::types;

    #[test]
    fn dump_type() {
        let btf = Btf::from_vmlinux().expect("failed to extract btf information from vmlinux");
        let ty = btf
            .type_by_kind::<types::Typedef<'_>>()
            .next()
            .expect("failed to extract first typedef");
        let mut dump = BtfDump::new(&btf, io::empty()).expect("failed to create btf dump");
        dump.dump_type(ty.type_id()).expect("failed to dump type");
    }

    #[test]
    fn emit_type_decl() {
        let btf = Btf::from_vmlinux().expect("failed to extract btf information from vmlinux");
        let ty = btf
            .type_by_kind::<types::DeclTag<'_>>()
            .filter_map(|t| t.next_type())
            .filter_map(|t| btf.type_by_id::<types::Func<'_>>(t.type_id()))
            .next()
            .expect("failed to extract first function prototype");
        let mut dump = BtfDump::new(&btf, io::empty()).expect("failed to create btf dump");
        dump.emit_type_decl(ty.type_id(), EmitTypeDeclOpts::default())
            .expect("failed to dump type");
    }
}
