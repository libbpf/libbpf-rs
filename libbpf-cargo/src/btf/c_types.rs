use scroll_derive::{IOread, Pread as DerivePread, Pwrite, SizeWith};

pub const BTF_MAGIC: u16 = 0xEB9F;
pub const BTF_VERSION: u8 = 1;

/// All offsets are in bytes relative to the end of this header
#[repr(C)]
#[derive(Debug, Clone, DerivePread, Pwrite, IOread, SizeWith)]
pub struct btf_header {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
    pub type_off: u32,
    pub type_len: u32,
    pub str_off: u32,
    pub str_len: u32,
}

#[repr(C)]
#[derive(Debug, Clone, DerivePread, Pwrite, IOread, SizeWith)]
pub struct btf_type {
    pub name_off: u32,
    pub info: u32,
    pub type_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone, DerivePread, Pwrite, IOread, SizeWith)]
pub struct btf_enum {
    pub name_off: u32,
    pub val: i32,
}

#[repr(C)]
#[derive(Debug, Clone, DerivePread, Pwrite, IOread, SizeWith)]
pub struct btf_array {
    pub val_type_id: u32,
    pub idx_type_id: u32,
    pub nelems: u32,
}

#[repr(C)]
#[derive(Debug, Clone, DerivePread, Pwrite, IOread, SizeWith)]
pub struct btf_member {
    pub name_off: u32,
    pub type_id: u32,
    pub offset: u32,
}

#[repr(C)]
#[derive(Debug, Clone, DerivePread, Pwrite, IOread, SizeWith)]
pub struct btf_param {
    pub name_off: u32,
    pub type_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone, DerivePread, Pwrite, IOread, SizeWith)]
pub struct btf_datasec_var {
    pub type_id: u32,
    pub offset: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Debug, Clone, DerivePread, Pwrite, IOread, SizeWith)]
pub struct btf_decl_tag {
    pub component_idx: i32,
}
