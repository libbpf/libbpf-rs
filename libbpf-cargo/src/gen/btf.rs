use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Deref;

use libbpf_rs::btf::TypeId;
use libbpf_rs::Btf;

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
