use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Deref;

use anyhow::bail;
use anyhow::Result;
use libbpf_rs::btf::BtfKind;
use libbpf_rs::btf::BtfType;
use libbpf_rs::btf::TypeId;
use libbpf_rs::btf_type_match;
use libbpf_rs::Btf;
use libbpf_rs::HasSize;

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
}
