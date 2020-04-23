use std::path::Path;

use crate::*;

/// Represents a BPF object file. An object may contain zero or more
/// [`Program`]s and [`Map`]s.
pub struct Object {}

impl Object {
    pub fn from_path<P: AsRef<Path>>(_path: P) -> Result<Self> {
        unimplemented!();
    }

    pub fn from_memory(_name: &str, _mem: &[u8]) -> Result<Self> {
        unimplemented!();
    }

    /// Override the generated name that would have been inferred from the constructor.
    pub fn name<T: AsRef<str>>(&mut self, _name: T) -> &mut Self {
        unimplemented!();
    }

    /// Option to parse map definitions non-strictly, allowing extra attributes/data
    pub fn relaxed_maps(&mut self) -> &mut Self {
        unimplemented!();
    }

    pub fn get_name(&self) -> &str {
        unimplemented!();
    }

    pub fn get_map<T: AsRef<str>>(&mut self, _name: T) -> Option<&mut Map> {
        unimplemented!();
    }

    pub fn get_prog<T: AsRef<str>>(&mut self, _name: T) -> Option<&mut Program> {
        unimplemented!();
    }
}

/// Represents a parsed but not yet loaded map.
pub struct Map {}

impl Map {
    pub fn name<T: AsRef<str>>(&mut self, _name: T) -> &mut Self {
        unimplemented!();
    }

    pub fn map_type(&mut self, _map_type: MapType) -> &mut Self {
        unimplemented!();
    }

    pub fn key_size(&mut self, _size: u32) -> &mut Self {
        unimplemented!();
    }

    pub fn value_size(&mut self, _size: u32) -> &mut Self {
        unimplemented!();
    }

    pub fn max_entries(&mut self, _entries: u32) -> &mut Self {
        unimplemented!();
    }

    pub fn numa_node(&mut self, _node: u32) -> &mut Self {
        unimplemented!();
    }

    pub fn btf_fd(&mut self, _fd: u32) -> &mut Self {
        unimplemented!();
    }

    pub fn btf_key_type_id(&mut self, _id: u32) -> &mut Self {
        unimplemented!();
    }

    pub fn btf_value_type_id(&mut self, _id: u32) -> &mut Self {
        unimplemented!();
    }

    pub fn map_ifindex(&mut self, _idx: u32) -> &mut Self {
        unimplemented!();
    }

    pub fn inner_map_fd(&mut self, _fd: u32) -> &mut Self {
        unimplemented!();
    }

    pub fn btf_vmlinux_value_type_id(&mut self, _id: u32) -> &mut Self {
        unimplemented!();
    }

    pub fn no_prealloc(&mut self) -> &mut Self {
        unimplemented!();
    }

    pub fn no_common_lru(&mut self) -> &mut Self {
        unimplemented!();
    }

    // TODO: more flags here:
    // https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L340-L341

    pub fn load(&mut self) -> Result<LoadedMap> {
        unimplemented!();
    }
}

/// Represents a created map.
///
/// The kernel ensure the atomicity and safety of operations on a `LoadedMap`. Therefore,
/// this handle is safe to clone and pass around between threads. This is essentially a
/// file descriptor.
///
/// Some methods require working with raw bytes. You may find libraries such as
/// [`plain`](https://crates.io/crates/plain) helpful.
#[derive(Clone)]
pub struct LoadedMap {}

impl LoadedMap {
    pub fn name(&self) -> &str {
        unimplemented!();
    }

    /// Returns a file descriptor to the underlying map.
    pub fn fd(&self) -> i64 {
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
    pub fn delete(&mut self, _key: &[u8]) -> Result<()> {
        unimplemented!();
    }

    /// Same as [`LoadedMap::lookup()`] except this also deletes the key from the map.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements.
    pub fn lookup_and_delete(
        &mut self,
        _key: &[u8],
        _flags: LoadedMapFlags,
    ) -> Result<Option<Vec<u8>>> {
        unimplemented!();
    }

    /// Update an element.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements. `value` must have exatly
    /// [`Map::value_size()`] elements.
    pub fn update(&mut self, _key: &[u8], _value: &[u8], _flags: LoadedMapFlags) -> Result<()> {
        unimplemented!();
    }
}

/// Flags to configure [`Map`] operations.
pub struct LoadedMapFlags {}

/// Type of a [`Map`]. Maps to `enum bpf_map_type` in kernel uapi.
#[non_exhaustive]
pub enum MapType {}

/// Represents a parsed but not yet loaded BPF program.
pub struct Program {}

impl Program {
    pub fn prog_type(&mut self, _prog_type: ProgramType) -> &mut Self {
        unimplemented!();
    }

    pub fn attach_type(&mut self, _attach_type: ProgramAttachType) -> &mut Self {
        unimplemented!();
    }

    pub fn ifindex(&mut self, _idx: i32) -> &mut Self {
        unimplemented!();
    }

    pub fn allow_override(&mut self) -> &mut Self {
        unimplemented!();
    }

    pub fn allow_multi(&mut self) -> &mut Self {
        unimplemented!();
    }

    pub fn replace(&mut self) -> &mut Self {
        unimplemented!();
    }

    // TODO: more flags here:
    // https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L267

    pub fn load(&mut self) -> Result<LoadedProgram> {
        unimplemented!();
    }
}

/// Type of a [`Program`]. Maps to `enum bpf_prog_type` in kernel uapi.
#[non_exhaustive]
pub enum ProgramType {}

/// Attach type of a [`Program`]. Maps to `enum bpf_attach_type` in kernel uapi.
#[non_exhaustive]
pub enum ProgramAttachType {}

/// Represents a loaded [`Program`].
///
/// The kernel ensure the atomicity and safety of operations on a `LoadedProgram`. Therefore,
/// this handle is safe to clone and pass around between threads. This is essentially a
/// file descriptor.
///
/// If you attempt to attach a `LoadedProgram` with the wrong attach method, the `attach_*`
/// method will fail with the appropriate error.
#[derive(Clone)]
pub struct LoadedProgram {}

impl LoadedProgram {
    pub fn name(&self) -> &str {
        unimplemented!();
    }

    /// Name of the section this `Program` belongs to.
    pub fn section(&self) -> &str {
        unimplemented!();
    }

    pub fn prog_type(&self) -> ProgramType {
        unimplemented!();
    }

    /// Returns a file descriptor to the underlying program.
    pub fn fd(&self) -> i64 {
        unimplemented!();
    }

    pub fn attach_type(&self) -> ProgramAttachType {
        unimplemented!();
    }

    pub fn attach_cgroup<T: AsRef<str>>(&mut self, _cgroup: T) -> Result<Link> {
        unimplemented!();
    }

    pub fn attach_perf_event(&mut self, _pfd: i64) -> Result<Link> {
        unimplemented!();
    }
}
