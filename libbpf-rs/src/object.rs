use std::path::Path;

use crate::*;

pub struct Object {}

impl Object {
    pub fn with_path<P: AsRef<Path>>(_path: P, _opts: ObjectOptions) -> Result<Self> {
        unimplemented!();
    }

    pub fn with_memory(_name: &str, _mem: &[u8], _opts: ObjectOptions) -> Result<Self> {
        unimplemented!();
    }

    pub fn name(&self) -> &str {
        unimplemented!();
    }

    pub fn maps(&self) -> Vec<&Map> {
        unimplemented!();
    }

    /// Acquire ownership of [`Map`] s in this [`Object`] for which `f` returns `true`.
    pub fn take_maps<F>(&mut self, _f: F) -> Vec<Map>
    where
        F: FnMut(&Map),
    {
        unimplemented!();
    }

    pub fn progs(&self) -> Vec<&Program> {
        unimplemented!();
    }

    /// Acquire ownership of [`Program`]s in this [`Object`] for which `f`
    /// returns `true`.
    pub fn take_progs<F>(&mut self, _f: F) -> Vec<Program>
    where
        F: FnMut(&Program),
    {
        unimplemented!();
    }
}

pub struct ObjectOptions {}

pub struct Map {}

impl Map {
    pub fn name(&self) -> &str {
        unimplemented!();
    }

    /// Key size in bytes
    pub fn key_size(&self) -> u32 {
        unimplemented!();
    }

    /// Value size in bytes
    pub fn value_size(&self) -> u32 {
        unimplemented!();
    }

    /// Returns map value as `Vec` of `u8`. You will most likely need to use `unsafe` to turn the
    /// buffer into something you can work with.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements.
    pub fn lookup(&self, _key: &[u8]) -> Option<Vec<u8>> {
        unimplemented!();
    }

    /// Deletes the element from the map. `Some(())` on success, `None` on failure.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements.
    pub fn delete(&self, _key: &[u8]) -> Option<()> {
        unimplemented!();
    }

    /// Same as [`Map::lookup()`] except this also deletes the key from the map.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements.
    pub fn lookup_and_delete(&self, _key: &[u8], _opts: MapOptions) -> Option<Vec<u8>> {
        unimplemented!();
    }

    /// Update an element.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements. `value` must have exatly
    /// [`Map::value_size()`] elements.
    ///
    /// Returns `Some(())` on success, `None` on failure.
    pub fn update(&self, _key: &[u8], _value: &[u8], _opts: MapOptions) -> Option<()> {
        unimplemented!();
    }
}

pub struct MapOptions {}

pub struct Program {}

impl Program {
    pub fn name(&self) -> &str {
        unimplemented!();
    }

    /// Name of the section this `Program` belongs to. This information is used by
    /// [`crate::link::Link`] constructors to determine where to attach the prog.
    pub fn section(&self) -> &str {
        unimplemented!();
    }

    pub fn prog_type(&self) -> ProgramType {
        unimplemented!();
    }

    pub fn attach_type(&self) -> ProgramAttachType {
        unimplemented!();
    }
}

pub enum ProgramType {}

pub enum ProgramAttachType {}
