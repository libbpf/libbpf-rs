use std::path::Path;

use crate::*;

/// Represents a BPF object file. An object may contain zero or more
/// [`Program`]s and [`Map`]s.
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

    /// Acquire ownership of [`Map`] s in this object for which `f` returns `true`.
    pub fn take_maps<F>(&mut self, _f: F) -> Vec<Map>
    where
        F: FnMut(&Map),
    {
        unimplemented!();
    }

    pub fn progs(&self) -> Vec<&Program> {
        unimplemented!();
    }

    /// Acquire ownership of [`Program`]s in this object for which `f` returns `true`.
    pub fn take_progs<F>(&mut self, _f: F) -> Vec<Program>
    where
        F: FnMut(&Program),
    {
        unimplemented!();
    }
}

/// Options to configure [`Object`] processing.
pub struct ObjectOptions {}

/// Represents a map.
///
/// Some methods require working with raw bytes. You may find libraries such as
/// [`plain`](https://crates.io/crates/plain) helpful.
pub struct Map {}

impl Map {
    pub fn name(&self) -> &str {
        unimplemented!();
    }

    pub fn map_type(&self) -> MapType {
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

    /// Returns map value as `Vec` of `u8`.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements.
    pub fn lookup(&self, _key: &[u8]) -> Result<Option<Vec<u8>>> {
        unimplemented!();
    }

    /// Deletes an element from the map.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements.
    pub fn delete(&self, _key: &[u8]) -> Result<()> {
        unimplemented!();
    }

    /// Same as [`Map::lookup()`] except this also deletes the key from the map.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements.
    pub fn lookup_and_delete(&self, _key: &[u8], _opts: MapOptions) -> Result<Option<Vec<u8>>> {
        unimplemented!();
    }

    /// Update an element.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements. `value` must have exatly
    /// [`Map::value_size()`] elements.
    pub fn update(&self, _key: &[u8], _value: &[u8], _opts: MapOptions) -> Result<()> {
        unimplemented!();
    }
}

/// Options to configure [`Map`] operations.
pub struct MapOptions {}

/// Type of a [`Map`]. Maps to `enum bpf_map_type` in kernel uapi.
///
/// Note this enum may gain more variants as feature are added to the kernel.
pub enum MapType {}

/// Represents a BPF program.
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

/// Type of a [`Program`]. Maps to `enum bpf_prog_type` in kernel uapi.
///
/// Note this enum may gain more variants as feature are added to the kernel.
pub enum ProgramType {}

/// Attach type of a [`Program`]. Maps to `enum bpf_attach_type` in kernel uapi.
///
/// Note this enum may gain more variants as feature are added to the kernel.
pub enum ProgramAttachType {}
