use std::cmp::{max, min};
use std::convert::TryFrom;
use std::ffi::{c_void, CStr, CString};
use std::mem::size_of;
use std::slice;

use anyhow::{bail, ensure, Result};
use scroll::Pread;

use crate::btf::c_types::*;
use crate::btf::*;

pub struct Btf<'a> {
    types: Vec<BtfType<'a>>,
    ptr_size: u32,
    string_table: &'a [u8],
    bpf_obj: *mut libbpf_sys::bpf_object,
}

impl<'a> Btf<'a> {
    pub fn new(name: &str, object_file: &[u8]) -> Result<Option<Self>> {
        let cname = CString::new(name)?;
        let mut obj_opts = libbpf_sys::bpf_object_open_opts::default();
        obj_opts.sz = std::mem::size_of::<libbpf_sys::bpf_object_open_opts>() as libbpf_sys::size_t;
        obj_opts.object_name = cname.as_ptr();
        let bpf_obj = unsafe {
            libbpf_sys::bpf_object__open_mem(
                object_file.as_ptr() as *const c_void,
                object_file.len() as u64,
                &obj_opts,
            )
        };
        let err = unsafe { libbpf_sys::libbpf_get_error(bpf_obj as *const _) };
        ensure!(err == 0, "Failed to bpf_object__open_mem: errno {}", err);

        let bpf_obj_btf = unsafe { libbpf_sys::bpf_object__btf(bpf_obj) };
        if bpf_obj_btf.is_null() {
            return Ok(None);
        }

        let num: u32 = 0x1234;
        let endianness = if num.to_le_bytes() == num.to_ne_bytes() {
            libbpf_sys::BTF_LITTLE_ENDIAN
        } else {
            libbpf_sys::BTF_BIG_ENDIAN
        };
        ensure!(
            unsafe { libbpf_sys::btf__set_endianness(bpf_obj_btf, endianness) } == 0,
            "Failed to set BTF endianness"
        );

        let ptr_size = unsafe { libbpf_sys::btf__pointer_size(bpf_obj_btf) };
        ensure!(ptr_size != 0, "Could not determine BTF pointer size");

        let mut raw_data_size = 0;
        let raw_data = unsafe { libbpf_sys::btf__get_raw_data(bpf_obj_btf, &mut raw_data_size) };
        ensure!(
            !raw_data.is_null() && raw_data_size > 0,
            "Could not get raw BTF data"
        );
        // `data` is valid as long as `bpf_obj` ptr is valid, so we're safe to conjure up this
        // `'a` lifetime
        let data: &'a [u8] =
            unsafe { slice::from_raw_parts(raw_data as *const u8, raw_data_size as usize) };

        // Read section header
        let hdr = data.pread::<btf_header>(0)?;
        ensure!(hdr.magic == BTF_MAGIC, "Invalid BTF magic");
        ensure!(
            hdr.version == BTF_VERSION,
            "Unsupported BTF version: {}",
            hdr.version
        );

        // String table
        let str_off = (hdr.hdr_len + hdr.str_off) as usize;
        let str_end = str_off + (hdr.str_len as usize);
        ensure!(str_end <= data.len(), "String table out of bounds");
        let str_data = &data[str_off..str_end];

        // Type table
        let type_off = (hdr.hdr_len + hdr.type_off) as usize;
        let type_end = type_off + (hdr.type_len as usize);
        ensure!(type_end <= data.len(), "Type table out of bounds");
        let type_data = &data[type_off..type_end];

        let mut btf = Btf::<'a> {
            // Type ID 0 is reserved for Void
            types: vec![BtfType::Void],
            ptr_size: ptr_size as u32,
            string_table: str_data,
            bpf_obj,
        };

        // Load all types
        let mut off: usize = 0;
        while off < hdr.type_len as usize {
            let t = btf.load_type(&type_data[off..])?;
            off += Btf::type_size(&t);
            btf.types.push(t);
        }

        Ok(Some(btf))
    }

    pub fn types(&self) -> &[BtfType<'a>] {
        &self.types
    }

    pub fn type_by_id(&self, type_id: u32) -> Result<&BtfType> {
        if (type_id as usize) < self.types.len() {
            Ok(&self.types[type_id as usize])
        } else {
            bail!("Invalid type_id: {}", type_id);
        }
    }

    pub fn size_of(&self, type_id: u32) -> Result<u32> {
        let skipped_type_id = self.skip_mods_and_typedefs(type_id)?;

        Ok(match self.type_by_id(skipped_type_id)? {
            BtfType::Int(t) => ((t.bits + 7) / 8).into(),
            BtfType::Ptr(_) => self.ptr_size,
            BtfType::Array(t) => t.nelems * self.size_of(t.val_type_id)?,
            BtfType::Struct(t) => t.size,
            BtfType::Union(t) => t.size,
            BtfType::Enum(t) => t.size,
            BtfType::Var(t) => self.size_of(t.type_id)?,
            BtfType::Datasec(t) => t.size,
            BtfType::Void
            | BtfType::Volatile(_)
            | BtfType::Const(_)
            | BtfType::Restrict(_)
            | BtfType::Typedef(_)
            | BtfType::FuncProto(_)
            | BtfType::Fwd(_)
            | BtfType::Func(_) => bail!("Cannot get size of type_id: {}", skipped_type_id),
        })
    }

    pub fn align_of(&self, type_id: u32) -> Result<u32> {
        let skipped_type_id = self.skip_mods_and_typedefs(type_id)?;

        Ok(match self.type_by_id(skipped_type_id)? {
            BtfType::Int(t) => min(self.ptr_size, ((t.bits + 7) / 8).into()),
            BtfType::Ptr(_) => self.ptr_size,
            BtfType::Array(t) => self.align_of(t.val_type_id)?,
            BtfType::Struct(t) | BtfType::Union(t) => {
                let mut align = 1;
                for m in &t.members {
                    align = max(align, self.align_of(m.type_id)?);
                }

                align
            }
            BtfType::Enum(t) => min(self.ptr_size, t.size),
            BtfType::Var(t) => self.align_of(t.type_id)?,
            BtfType::Datasec(t) => t.size,
            BtfType::Void
            | BtfType::Volatile(_)
            | BtfType::Const(_)
            | BtfType::Restrict(_)
            | BtfType::Typedef(_)
            | BtfType::FuncProto(_)
            | BtfType::Fwd(_)
            | BtfType::Func(_) => bail!("Cannot get alignment of type_id: {}", skipped_type_id),
        })
    }

    pub fn skip_mods_and_typedefs(&self, mut type_id: u32) -> Result<u32> {
        loop {
            match self.type_by_id(type_id)? {
                BtfType::Volatile(t) => type_id = t.type_id,
                BtfType::Const(t) => type_id = t.type_id,
                BtfType::Restrict(t) => type_id = t.type_id,
                BtfType::Typedef(t) => type_id = t.type_id,
                _ => return Ok(type_id),
            };
        }
    }

    fn load_type(&self, data: &'a [u8]) -> Result<BtfType<'a>> {
        let t = data.pread::<btf_type>(0)?;
        let extra = &data[size_of::<btf_type>()..];
        let kind = (t.info >> 24) & 0xf;

        match BtfKind::try_from(kind)? {
            BtfKind::Void => {
                let _ = BtfType::Void; // Silence unused variant warning
                bail!("Cannot load Void type");
            }
            BtfKind::Int => self.load_int(&t, extra),
            BtfKind::Ptr => Ok(BtfType::Ptr(BtfPtr {
                pointee_type: t.type_id,
            })),
            BtfKind::Array => self.load_array(extra),
            BtfKind::Struct => self.load_struct(&t, extra),
            BtfKind::Union => self.load_union(&t, extra),
            BtfKind::Enum => self.load_enum(&t, extra),
            BtfKind::Fwd => self.load_fwd(&t),
            BtfKind::Typedef => Ok(BtfType::Typedef(BtfTypedef {
                name: self.get_btf_str(t.name_off as usize)?,
                type_id: t.type_id,
            })),
            BtfKind::Volatile => Ok(BtfType::Volatile(BtfVolatile { type_id: t.type_id })),
            BtfKind::Const => Ok(BtfType::Const(BtfConst { type_id: t.type_id })),
            BtfKind::Restrict => Ok(BtfType::Restrict(BtfRestrict { type_id: t.type_id })),
            BtfKind::Func => Ok(BtfType::Func(BtfFunc {
                name: self.get_btf_str(t.name_off as usize)?,
                type_id: t.type_id,
            })),
            BtfKind::FuncProto => self.load_func_proto(&t, extra),
            BtfKind::Var => self.load_var(&t, extra),
            BtfKind::Datasec => self.load_datasec(&t, extra),
        }
    }

    fn load_int(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        let info = extra.pread::<u32>(0)?;
        let enc: u8 = ((info >> 24) & 0xf) as u8;
        let off: u8 = ((info >> 16) & 0xff) as u8;
        let bits: u8 = (info & 0xff) as u8;
        Ok(BtfType::Int(BtfInt {
            name: self.get_btf_str(t.name_off as usize)?,
            bits,
            offset: off,
            encoding: BtfIntEncoding::try_from(enc)?,
        }))
    }

    fn load_array(&self, extra: &'a [u8]) -> Result<BtfType<'a>> {
        let info = extra.pread::<btf_array>(0)?;
        Ok(BtfType::Array(BtfArray {
            nelems: info.nelems,
            index_type_id: info.idx_type_id,
            val_type_id: info.val_type_id,
        }))
    }

    fn load_struct(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        Ok(BtfType::Struct(BtfComposite {
            name: self.get_btf_str(t.name_off as usize)?,
            is_struct: true,
            size: t.type_id,
            members: self.load_members(t, extra)?,
        }))
    }

    fn load_union(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        Ok(BtfType::Union(BtfComposite {
            name: self.get_btf_str(t.name_off as usize)?,
            is_struct: false,
            size: t.type_id,
            members: self.load_members(t, extra)?,
        }))
    }

    fn load_members(&self, t: &btf_type, extra: &'a [u8]) -> Result<Vec<BtfMember<'a>>> {
        let mut res = Vec::new();
        let mut off: usize = 0;
        let bits = Self::get_kind(t.info);

        for _ in 0..Btf::get_vlen(t.info) {
            let m = extra.pread::<btf_member>(off)?;
            res.push(BtfMember {
                name: self.get_btf_str(m.name_off as usize)?,
                type_id: m.type_id,
                bit_size: if bits { (m.offset >> 24) as u8 } else { 0 },
                bit_offset: if bits { m.offset & 0xffffff } else { m.offset },
            });

            off += size_of::<btf_member>();
        }

        Ok(res)
    }

    fn load_enum(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        let mut vals = Vec::new();
        let mut off: usize = 0;

        for _ in 0..Btf::get_vlen(t.info) {
            let v = extra.pread::<btf_enum>(off)?;
            vals.push(BtfEnumValue {
                name: self.get_btf_str(v.name_off as usize)?,
                value: v.val,
            });

            off += size_of::<btf_enum>();
        }

        Ok(BtfType::Enum(BtfEnum {
            name: self.get_btf_str(t.name_off as usize)?,
            size: t.type_id,
            values: vals,
        }))
    }

    fn load_fwd(&self, t: &btf_type) -> Result<BtfType<'a>> {
        Ok(BtfType::Fwd(BtfFwd {
            name: self.get_btf_str(t.name_off as usize)?,
            kind: if Self::get_kind(t.info) {
                BtfFwdKind::Union
            } else {
                BtfFwdKind::Struct
            },
        }))
    }

    fn load_func_proto(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        let mut params = Vec::new();
        let mut off: usize = 0;

        for _ in 0..Btf::get_vlen(t.info) {
            let p = extra.pread::<btf_param>(off)?;
            params.push(BtfFuncParam {
                name: self.get_btf_str(p.name_off as usize)?,
                type_id: p.type_id,
            });

            off += size_of::<btf_param>();
        }

        Ok(BtfType::FuncProto(BtfFuncProto {
            ret_type_id: t.type_id,
            params,
        }))
    }

    fn load_var(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        let kind = extra.pread::<u32>(0)?;
        Ok(BtfType::Var(BtfVar {
            name: self.get_btf_str(t.name_off as usize)?,
            type_id: t.type_id,
            linkage: BtfVarLinkage::try_from(kind)?,
        }))
    }

    fn load_datasec(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        let mut vars = Vec::new();
        let mut off: usize = 0;

        for _ in 0..Btf::get_vlen(t.info) {
            let v = extra.pread::<btf_datasec_var>(off)?;
            vars.push(BtfDatasecVar {
                type_id: v.type_id,
                offset: v.offset,
                size: v.size,
            });

            off += size_of::<btf_datasec_var>();
        }

        Ok(BtfType::Datasec(BtfDatasec {
            name: self.get_btf_str(t.name_off as usize)?,
            size: t.type_id,
            vars,
        }))
    }

    /// Returns size of type on disk in .BTF section
    fn type_size(t: &BtfType) -> usize {
        let common = size_of::<btf_type>();
        match t {
            BtfType::Void => 0,
            BtfType::Ptr(_)
            | BtfType::Fwd(_)
            | BtfType::Typedef(_)
            | BtfType::Volatile(_)
            | BtfType::Const(_)
            | BtfType::Restrict(_)
            | BtfType::Func(_) => common,
            BtfType::Int(_) | BtfType::Var(_) => common + size_of::<u32>(),
            BtfType::Array(_) => common + size_of::<btf_array>(),
            BtfType::Struct(t) => common + t.members.len() * size_of::<btf_member>(),
            BtfType::Union(t) => common + t.members.len() * size_of::<btf_member>(),
            BtfType::Enum(t) => common + t.values.len() * size_of::<btf_enum>(),
            BtfType::FuncProto(t) => common + t.params.len() * size_of::<btf_param>(),
            BtfType::Datasec(t) => common + t.vars.len() * size_of::<btf_datasec_var>(),
        }
    }

    fn get_vlen(info: u32) -> u32 {
        info & 0xffff
    }

    fn get_kind(info: u32) -> bool {
        (info >> 31) == 1
    }

    fn get_btf_str(&self, offset: usize) -> Result<&'a str> {
        let c_str = unsafe { CStr::from_ptr(&self.string_table[offset] as *const u8 as *const i8) };
        Ok(c_str.to_str()?)
    }
}

impl<'a> Drop for Btf<'a> {
    fn drop(&mut self) {
        unsafe {
            libbpf_sys::bpf_object__close(self.bpf_obj);
        }
    }
}
