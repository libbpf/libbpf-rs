use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write;
use std::mem::size_of;
use std::ops::Deref;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use libbpf_rs::btf::BtfKind;
use libbpf_rs::btf::BtfType;
use libbpf_rs::btf::TypeId;
use libbpf_rs::btf_type_match;
use libbpf_rs::Btf;
use libbpf_rs::HasSize;
use libbpf_rs::ReferencesType;

const ANON_PREFIX: &str = "__anon_";

pub(super) struct GenBtf<'s> {
    btf: Btf<'s>,
    // We use refcell here because the design of this type unfortunately causes a lot of borrowing
    // issues. (Taking BtfType as an argument of a &mut self method requires having multiple
    // borrows of self, since BtfType borrows from self).
    //
    // This way we avoid having any of those issues as we use internal mutability.
    anon_types: RefCell<HashMap<TypeId, usize>>,
}

impl<'s> From<Btf<'s>> for GenBtf<'s> {
    fn from(btf: Btf<'s>) -> GenBtf<'s> {
        Self {
            btf,
            anon_types: Default::default(),
        }
    }
}

impl<'s> Deref for GenBtf<'s> {
    type Target = Btf<'s>;
    fn deref(&self) -> &Self::Target {
        &self.btf
    }
}

impl<'s> GenBtf<'s> {
    fn size_of(&self, ty: BtfType<'s>) -> Result<usize> {
        let ty = ty.skip_mods_and_typedefs();

        Ok(btf_type_match!(match ty {
            BtfKind::Int(t) => ((t.bits + 7) / 8).into(),
            BtfKind::Ptr => self.ptr_size()?,
            BtfKind::Array(t) => t.capacity() * self.size_of(t.contained_type())?,
            BtfKind::Struct(t) => t.size(),
            BtfKind::Union(t) => t.size(),
            BtfKind::Enum(t) => t.size(),
            BtfKind::Enum64(t) => t.size(),
            BtfKind::Var(t) => self.size_of(t.referenced_type())?,
            BtfKind::DataSec(t) => t.size(),
            BtfKind::Float(t) => t.size(),
            BtfKind::Void => bail!("Cannot get size of type_id: {ty:?}"),
            BtfKind::Volatile => bail!("Cannot get size of type_id: {ty:?}"),
            BtfKind::Const => bail!("Cannot get size of type_id: {ty:?}"),
            BtfKind::Restrict => bail!("Cannot get size of type_id: {ty:?}"),
            BtfKind::Typedef => bail!("Cannot get size of type_id: {ty:?}"),
            BtfKind::FuncProto => bail!("Cannot get size of type_id: {ty:?}"),
            BtfKind::Fwd => bail!("Cannot get size of type_id: {ty:?}"),
            BtfKind::Func => bail!("Cannot get size of type_id: {ty:?}"),
            BtfKind::DeclTag => bail!("Cannot get size of type_id: {ty:?}"),
            BtfKind::TypeTag => bail!("Cannot get size of type_id: {ty:?}"),
        }))
    }

    fn get_type_name_handling_anon_types(&self, t: &BtfType<'s>) -> Cow<'s, str> {
        match t.name() {
            None => {
                let mut anon_table = self.anon_types.borrow_mut();
                let len = anon_table.len() + 1; // use 1 index anon ids for backwards compat
                let anon_id = anon_table.entry(t.type_id()).or_insert(len);
                format!("{}{}", ANON_PREFIX, anon_id).into()
            }
            Some(n) => n.to_string_lossy(),
        }
    }

    /// Returns the rust-ified type declaration of `ty` in string format.
    ///
    /// Rule of thumb is `ty` must be a type a variable can have.
    ///
    /// Type qualifiers are discarded (eg `const`, `volatile`, etc).
    fn type_declaration(&self, ty: BtfType<'s>) -> Result<String> {
        let ty = ty.skip_mods_and_typedefs();

        let s = btf_type_match!(match ty {
            BtfKind::Void => "std::ffi::c_void".to_string(),
            BtfKind::Int(t) => {
                let width = match (t.bits + 7) / 8 {
                    1 => "8",
                    2 => "16",
                    4 => "32",
                    8 => "64",
                    16 => "128",
                    _ => bail!("Invalid integer width"),
                };

                match t.encoding {
                    types::IntEncoding::Signed => format!("i{width}"),
                    types::IntEncoding::Bool => {
                        assert!(t.bits as usize == (size_of::<bool>() * 8));
                        "bool".to_string()
                    }
                    types::IntEncoding::Char | types::IntEncoding::None => format!("u{width}"),
                }
            }
            BtfKind::Float(t) => {
                let width = match t.size() {
                    2 => bail!("Unsupported float width"),
                    4 => "32",
                    8 => "64",
                    12 => bail!("Unsupported float width"),
                    16 => bail!("Unsupported float width"),
                    _ => bail!("Invalid float width"),
                };

                format!("f{width}")
            }
            BtfKind::Ptr(t) => {
                let pointee_ty = self.type_declaration(t.referenced_type())?;

                format!("*mut {pointee_ty}")
            }
            BtfKind::Array(t) => {
                let val_ty = self.type_declaration(t.contained_type())?;

                format!("[{}; {}]", val_ty, t.capacity())
            }
            BtfKind::Struct => self.get_type_name_handling_anon_types(&ty).into_owned(),
            BtfKind::Union => self.get_type_name_handling_anon_types(&ty).into_owned(),
            BtfKind::Enum => self.get_type_name_handling_anon_types(&ty).into_owned(),
            BtfKind::Enum64 => self.get_type_name_handling_anon_types(&ty).into_owned(),
            //    // The only way a variable references a function is through a function pointer.
            //    // Return c_void here so the final def will look like `*mut c_void`.
            //    //
            //    // It's not like rust code can call a function inside a bpf prog either so we don't
            //    // really need a full definition. `void *` is totally sufficient for sharing a pointer.
            BtfKind::Func => "std::ffi::c_void".to_string(),
            BtfKind::Var(t) => self.type_declaration(t.referenced_type())?,
            BtfKind::Fwd => bail!("Invalid type: {ty:?}"),
            BtfKind::FuncProto => bail!("Invalid type: {ty:?}"),
            BtfKind::DataSec => bail!("Invalid type: {ty:?}"),
            BtfKind::Typedef => bail!("Invalid type: {ty:?}"),
            BtfKind::Volatile => bail!("Invalid type: {ty:?}"),
            BtfKind::Const => bail!("Invalid type: {ty:?}"),
            BtfKind::Restrict => bail!("Invalid type: {ty:?}"),
            BtfKind::DeclTag => bail!("Invalid type: {ty:?}"),
            BtfKind::TypeTag => bail!("Invalid type: {ty:?}"),
        });
        Ok(s)
    }

    /// Returns an expression that evaluates to the Default value
    /// of a type(typeid) in string form.
    ///
    /// To be used when creating a impl Default for a structure
    ///
    /// Rule of thumb is `ty` must be a type a variable can have.
    ///
    /// Type qualifiers are discarded (eg `const`, `volatile`, etc).
    fn type_default(&self, ty: BtfType<'s>) -> Result<String> {
        let ty = ty.skip_mods_and_typedefs();

        Ok(btf_type_match!(match ty {
            BtfKind::Void => bail!("Invalid type: {ty:?}"),
            BtfKind::Int => format!("{}::default()", self.type_declaration(ty)?),
            BtfKind::Float => format!("{}::default()", self.type_declaration(ty)?),
            BtfKind::Ptr => "std::ptr::null_mut()".to_string(),
            BtfKind::Array(t) => {
                format!(
                    "[{}; {}]",
                    self.type_default(t.contained_type())
                        .map_err(|err| anyhow!("in {ty:?}: {err}"))?,
                    t.capacity()
                )
            }
            BtfKind::Struct =>
                format!("{}::default()", self.get_type_name_handling_anon_types(&ty),),
            BtfKind::Union =>
                format!("{}::default()", self.get_type_name_handling_anon_types(&ty),),
            BtfKind::Enum => format!("{}::default()", self.get_type_name_handling_anon_types(&ty),),
            BtfKind::Enum64 =>
                format!("{}::default()", self.get_type_name_handling_anon_types(&ty),),
            BtfKind::Var(t) =>
                format!("{}::default()", self.type_declaration(t.referenced_type())?),
            BtfKind::Func => bail!("Invalid type: {ty:?}"),
            BtfKind::Fwd => bail!("Invalid type: {ty:?}"),
            BtfKind::FuncProto => bail!("Invalid type: {ty:?}"),
            BtfKind::DataSec => bail!("Invalid type: {ty:?}"),
            BtfKind::Typedef => bail!("Invalid type: {ty:?}"),
            BtfKind::Volatile => bail!("Invalid type: {ty:?}"),
            BtfKind::Const => bail!("Invalid type: {ty:?}"),
            BtfKind::Restrict => bail!("Invalid type: {ty:?}"),
            BtfKind::DeclTag => bail!("Invalid type: {ty:?}"),
            BtfKind::TypeTag => bail!("Invalid type: {ty:?}"),
        }))
    }
}
