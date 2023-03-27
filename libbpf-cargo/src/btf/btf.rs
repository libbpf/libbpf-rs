use std::cmp::max;
use std::cmp::min;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::ffi::c_void;
use std::ffi::CStr;
use std::ffi::CString;
use std::fmt::Write;
use std::marker::PhantomData;
use std::mem::size_of;
use std::os::raw::c_char;
use std::os::raw::c_ulong;
use std::ptr;
use std::slice;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use anyhow::Result;
use scroll::Pread;

use crate::btf::btf;
use crate::btf::c_types::btf_array;
use crate::btf::c_types::btf_datasec_var;
use crate::btf::c_types::btf_decl_tag;
use crate::btf::c_types::btf_enum;
use crate::btf::c_types::btf_header;
use crate::btf::c_types::btf_member;
use crate::btf::c_types::btf_param;
use crate::btf::c_types::btf_type;
use crate::btf::c_types::BTF_MAGIC;
use crate::btf::c_types::BTF_VERSION;
use crate::btf::BtfArray;
use crate::btf::BtfComposite;
use crate::btf::BtfConst;
use crate::btf::BtfDatasec;
use crate::btf::BtfDatasecVar;
use crate::btf::BtfDeclTag;
use crate::btf::BtfEnum;
use crate::btf::BtfEnumValue;
use crate::btf::BtfFloat;
use crate::btf::BtfFunc;
use crate::btf::BtfFuncParam;
use crate::btf::BtfFuncProto;
use crate::btf::BtfFwd;
use crate::btf::BtfFwdKind;
use crate::btf::BtfInt;
use crate::btf::BtfIntEncoding;
use crate::btf::BtfKind;
use crate::btf::BtfMember;
use crate::btf::BtfPtr;
use crate::btf::BtfRestrict;
use crate::btf::BtfType;
use crate::btf::BtfTypeTag;
use crate::btf::BtfTypedef;
use crate::btf::BtfVar;
use crate::btf::BtfVarLinkage;
use crate::btf::BtfVolatile;
use crate::gen::BpfObj;

const ANON_PREFIX: &str = "__anon_";

fn get_vlen(info: u32) -> u32 {
    info & 0xffff
}

fn get_kind_flag(info: u32) -> bool {
    (info >> 31) == 1
}

fn get_kind(info: u32) -> u32 {
    (info >> 24) & 0x1f
}

struct BtfLoader<'dat> {
    /// Counter for anonymous types.
    anon_count: u32,
    /// Phantom data for the type's lifetime. Necessary only to avoid having to
    /// push it to each method.
    _phantom: PhantomData<&'dat ()>,
}

impl<'dat> BtfLoader<'dat> {
    /// Load all BTF types.
    fn load(type_data: &'dat [u8], string_table: &'dat [u8]) -> Result<Vec<BtfType<'dat>>> {
        let mut slf = Self {
            anon_count: 0,
            _phantom: PhantomData,
        };
        slf.load_now(type_data, string_table)
    }

    fn load_now(
        &mut self,
        type_data: &'dat [u8],
        string_table: &'dat [u8],
    ) -> Result<Vec<BtfType<'dat>>> {
        let mut off: usize = 0;
        // Type ID 0 is reserved for Void
        let mut types = vec![BtfType::Void];

        while off < type_data.len() {
            let t = self.load_type(string_table, &type_data[off..])?;
            off += Self::type_size(&t);
            types.push(t);
        }

        Ok(types)
    }

    fn load_type(&mut self, string_table: &'dat [u8], data: &'dat [u8]) -> Result<BtfType<'dat>> {
        let t = data.pread::<btf_type>(0)?;
        let extra = &data[size_of::<btf_type>()..];
        let kind = get_kind(t.info);

        match BtfKind::try_from(kind)? {
            BtfKind::Void => {
                let _ = BtfType::Void; // Silence unused variant warning
                bail!("Cannot load Void type");
            }
            BtfKind::Int => Self::load_int(string_table, &t, extra),
            BtfKind::Float => Self::load_float(string_table, &t),
            BtfKind::Ptr => Ok(BtfType::Ptr(BtfPtr {
                pointee_type: t.type_id,
            })),
            BtfKind::Array => Self::load_array(extra),
            BtfKind::Struct => self.load_struct(string_table, &t, extra),
            BtfKind::Union => self.load_union(string_table, &t, extra),
            BtfKind::Enum => self.load_enum(string_table, &t, extra),
            BtfKind::Fwd => Self::load_fwd(string_table, &t),
            BtfKind::Typedef => Ok(BtfType::Typedef(BtfTypedef {
                name: Self::get_btf_str(string_table, t.name_off as usize)?,
                type_id: t.type_id,
            })),
            BtfKind::Volatile => Ok(BtfType::Volatile(BtfVolatile { type_id: t.type_id })),
            BtfKind::Const => Ok(BtfType::Const(BtfConst { type_id: t.type_id })),
            BtfKind::Restrict => Ok(BtfType::Restrict(BtfRestrict { type_id: t.type_id })),
            BtfKind::Func => Ok(BtfType::Func(BtfFunc {
                name: Self::get_btf_str(string_table, t.name_off as usize)?,
                type_id: t.type_id,
            })),
            BtfKind::FuncProto => Self::load_func_proto(string_table, &t, extra),
            BtfKind::Var => Self::load_var(string_table, &t, extra),
            BtfKind::Datasec => Self::load_datasec(string_table, &t, extra),
            BtfKind::DeclTag => Self::load_decl_tag(string_table, &t, extra),
            BtfKind::TypeTag => Ok(BtfType::TypeTag(BtfTypeTag {
                name: Self::get_btf_str(string_table, t.name_off as usize)?,
                type_id: t.type_id,
            })),
        }
    }

    fn load_int(
        string_table: &'dat [u8],
        t: &btf_type,
        extra: &'dat [u8],
    ) -> Result<BtfType<'dat>> {
        let info = extra.pread::<u32>(0)?;
        let enc: u8 = ((info >> 24) & 0xf) as u8;
        let off: u8 = ((info >> 16) & 0xff) as u8;
        let bits: u8 = (info & 0xff) as u8;
        Ok(BtfType::Int(BtfInt {
            name: Self::get_btf_str(string_table, t.name_off as usize)?,
            bits,
            offset: off,
            encoding: BtfIntEncoding::try_from(enc)?,
        }))
    }

    fn load_float(string_table: &'dat [u8], t: &btf_type) -> Result<BtfType<'dat>> {
        Ok(BtfType::Float(BtfFloat {
            name: Self::get_btf_str(string_table, t.name_off as usize)?,
            size: t.type_id,
        }))
    }

    fn load_array(extra: &'dat [u8]) -> Result<BtfType<'dat>> {
        let info = extra.pread::<btf_array>(0)?;
        Ok(BtfType::Array(BtfArray {
            nelems: info.nelems,
            index_type_id: info.idx_type_id,
            val_type_id: info.val_type_id,
        }))
    }

    fn load_struct(
        &mut self,
        string_table: &'dat [u8],
        t: &btf_type,
        extra: &'dat [u8],
    ) -> Result<BtfType<'dat>> {
        let name = match Self::get_btf_str(string_table, t.name_off as usize)? {
            "" => {
                self.anon_count += 1;
                format!("{}{}", ANON_PREFIX, self.anon_count)
            }
            n => n.to_string(),
        };
        Ok(BtfType::Struct(BtfComposite {
            name,
            is_struct: true,
            size: t.type_id,
            members: Self::load_members(string_table, t, extra)?,
        }))
    }

    fn load_union(
        &mut self,
        string_table: &'dat [u8],
        t: &btf_type,
        extra: &'dat [u8],
    ) -> Result<BtfType<'dat>> {
        let name = match Self::get_btf_str(string_table, t.name_off as usize)? {
            "" => {
                self.anon_count += 1;
                format!("{}{}", ANON_PREFIX, self.anon_count)
            }
            n => n.to_string(),
        };
        Ok(BtfType::Union(BtfComposite {
            name,
            is_struct: false,
            size: t.type_id,
            members: Self::load_members(string_table, t, extra)?,
        }))
    }

    fn load_members(
        string_table: &'dat [u8],
        t: &btf_type,
        extra: &'dat [u8],
    ) -> Result<Vec<BtfMember<'dat>>> {
        let mut res = Vec::new();
        let mut off: usize = 0;
        let bits = get_kind_flag(t.info);

        for _ in 0..get_vlen(t.info) {
            let m = extra.pread::<btf_member>(off)?;
            res.push(BtfMember {
                name: Self::get_btf_str(string_table, m.name_off as usize)?,
                type_id: m.type_id,
                bit_size: if bits { (m.offset >> 24) as u8 } else { 0 },
                bit_offset: if bits { m.offset & 0xffffff } else { m.offset },
            });

            off += size_of::<btf_member>();
        }

        Ok(res)
    }

    fn load_enum(
        &mut self,
        string_table: &'dat [u8],
        t: &btf_type,
        extra: &'dat [u8],
    ) -> Result<BtfType<'dat>> {
        let name = match Self::get_btf_str(string_table, t.name_off as usize)? {
            "" => {
                self.anon_count += 1;
                format!("{}{}", ANON_PREFIX, self.anon_count)
            }
            n => n.to_string(),
        };

        let mut vals = Vec::new();
        let mut off: usize = 0;
        for _ in 0..get_vlen(t.info) {
            let v = extra.pread::<btf_enum>(off)?;
            vals.push(BtfEnumValue {
                name: Self::get_btf_str(string_table, v.name_off as usize)?,
                value: v.val,
            });

            off += size_of::<btf_enum>();
        }

        Ok(BtfType::Enum(BtfEnum {
            name,
            size: t.type_id,
            values: vals,
        }))
    }

    fn load_fwd(string_table: &'dat [u8], t: &btf_type) -> Result<BtfType<'dat>> {
        Ok(BtfType::Fwd(BtfFwd {
            name: Self::get_btf_str(string_table, t.name_off as usize)?,
            kind: if get_kind_flag(t.info) {
                BtfFwdKind::Union
            } else {
                BtfFwdKind::Struct
            },
        }))
    }

    fn load_func_proto(
        string_table: &'dat [u8],
        t: &btf_type,
        extra: &'dat [u8],
    ) -> Result<BtfType<'dat>> {
        let mut params = Vec::new();
        let mut off: usize = 0;

        for _ in 0..get_vlen(t.info) {
            let p = extra.pread::<btf_param>(off)?;
            params.push(BtfFuncParam {
                name: Self::get_btf_str(string_table, p.name_off as usize)?,
                type_id: p.type_id,
            });

            off += size_of::<btf_param>();
        }

        Ok(BtfType::FuncProto(BtfFuncProto {
            ret_type_id: t.type_id,
            params,
        }))
    }

    fn load_var(
        string_table: &'dat [u8],
        t: &btf_type,
        extra: &'dat [u8],
    ) -> Result<BtfType<'dat>> {
        let kind = extra.pread::<u32>(0)?;
        Ok(BtfType::Var(BtfVar {
            name: Self::get_btf_str(string_table, t.name_off as usize)?,
            type_id: t.type_id,
            linkage: BtfVarLinkage::try_from(kind)?,
        }))
    }

    fn load_datasec(
        string_table: &'dat [u8],
        t: &btf_type,
        extra: &'dat [u8],
    ) -> Result<BtfType<'dat>> {
        let mut vars = Vec::new();
        let mut off: usize = 0;

        for _ in 0..get_vlen(t.info) {
            let v = extra.pread::<btf_datasec_var>(off)?;
            vars.push(BtfDatasecVar {
                type_id: v.type_id,
                offset: v.offset,
                size: v.size,
            });

            off += size_of::<btf_datasec_var>();
        }

        Ok(BtfType::Datasec(BtfDatasec {
            name: Self::get_btf_str(string_table, t.name_off as usize)?,
            size: t.type_id,
            vars,
        }))
    }

    fn load_decl_tag(
        string_table: &'dat [u8],
        t: &btf_type,
        extra: &'dat [u8],
    ) -> Result<BtfType<'dat>> {
        let decl_tag = extra.pread::<btf_decl_tag>(0)?;
        Ok(BtfType::DeclTag(BtfDeclTag {
            name: Self::get_btf_str(string_table, t.name_off as usize)?,
            type_id: t.type_id,
            component_idx: decl_tag.component_idx,
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
            | BtfType::Func(_)
            | BtfType::Float(_)
            | BtfType::TypeTag(_) => common,
            BtfType::Int(_) | BtfType::Var(_) => common + size_of::<u32>(),
            BtfType::Array(_) => common + size_of::<btf_array>(),
            BtfType::Struct(t) => common + t.members.len() * size_of::<btf_member>(),
            BtfType::Union(t) => common + t.members.len() * size_of::<btf_member>(),
            BtfType::Enum(t) => common + t.values.len() * size_of::<btf_enum>(),
            BtfType::FuncProto(t) => common + t.params.len() * size_of::<btf_param>(),
            BtfType::Datasec(t) => common + t.vars.len() * size_of::<btf_datasec_var>(),
            BtfType::DeclTag(_) => common + size_of::<btf_decl_tag>(),
        }
    }

    fn get_btf_str(string_table: &[u8], offset: usize) -> Result<&str> {
        let c_str = unsafe { CStr::from_ptr(&string_table[offset] as *const u8 as *const c_char) };
        Ok(c_str.to_str()?)
    }
}

pub struct Btf {
    /// SAFETY: We must not hand out references with a 'static lifetime to
    ///         this member. They should never outlive `self`.
    types: Vec<BtfType<'static>>,
    ptr_size: u32,
    /// Copy of the raw BTF data from the BPF object.
    ///
    /// SAFETY: Needs to stay last to be dropped last, as other members
    ///         reference it. We also must not move out of it while references
    ///         to it are present.
    _raw_data: Box<[u8]>,
}

impl Btf {
    pub fn new(name: &str, object_file: &[u8]) -> Result<Option<Self>> {
        let cname = CString::new(name)?;
        let obj_opts = libbpf_sys::bpf_object_open_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_object_open_opts>() as libbpf_sys::size_t,
            object_name: cname.as_ptr(),
            ..Default::default()
        };
        let bpf_obj = unsafe {
            libbpf_sys::bpf_object__open_mem(
                object_file.as_ptr() as *const c_void,
                object_file.len() as c_ulong,
                &obj_opts,
            )
        };

        ensure!(!bpf_obj.is_null(), "Failed to bpf_object__open_mem");

        let err = unsafe { libbpf_sys::libbpf_get_error(bpf_obj as *const _) };
        ensure!(err == 0, "Failed to bpf_object__open_mem: errno {}", err);

        let mut bpf_obj = BpfObj::new(ptr::NonNull::new(bpf_obj).unwrap());
        let bpf_obj_btf = unsafe { libbpf_sys::bpf_object__btf(bpf_obj.as_mut_ptr()) };
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
        let raw_data = unsafe { libbpf_sys::btf__raw_data(bpf_obj_btf, &mut raw_data_size) };
        ensure!(
            !raw_data.is_null() && raw_data_size > 0,
            "Could not get raw BTF data"
        );
        let raw_data_copy =
            unsafe { slice::from_raw_parts(raw_data as *const u8, raw_data_size as usize) }
                .to_vec()
                .into_boxed_slice();

        // `data` is valid as long as `raw_data_copy` is valid, so we're safe to
        // conjure up this `'static` lifetime, as long as we make sure that
        // references carrying it do not leave the `Btf` object itself.
        let data: &'static [u8] = unsafe {
            slice::from_raw_parts(raw_data_copy.as_ptr() as *const u8, raw_data_size as usize)
        };

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

        let btf = Btf {
            _raw_data: raw_data_copy,
            types: BtfLoader::load(type_data, str_data)?,
            ptr_size: ptr_size as u32,
        };

        Ok(Some(btf))
    }

    pub fn types(&self) -> &[BtfType<'_>] {
        &self.types
    }

    pub fn type_by_id(&self, type_id: u32) -> Result<&BtfType> {
        if (type_id as usize) < self.types.len() {
            Ok(&self.types[type_id as usize])
        } else {
            bail!("Invalid type_id: {}", type_id);
        }
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
            BtfType::Float(t) => min(self.ptr_size, t.size),
            BtfType::Void
            | BtfType::Volatile(_)
            | BtfType::Const(_)
            | BtfType::Restrict(_)
            | BtfType::Typedef(_)
            | BtfType::FuncProto(_)
            | BtfType::Fwd(_)
            | BtfType::Func(_)
            | BtfType::DeclTag(_)
            | BtfType::TypeTag(_) => bail!("Cannot get alignment of type_id: {}", skipped_type_id),
        })
    }

    pub fn skip_mods_and_typedefs(&self, mut type_id: u32) -> Result<u32> {
        loop {
            match self.type_by_id(type_id)? {
                BtfType::Volatile(t) => type_id = t.type_id,
                BtfType::Const(t) => type_id = t.type_id,
                BtfType::Restrict(t) => type_id = t.type_id,
                BtfType::Typedef(t) => type_id = t.type_id,
                BtfType::TypeTag(t) => type_id = t.type_id,
                BtfType::Void
                | BtfType::Int(_)
                | BtfType::Float(_)
                | BtfType::Ptr(_)
                | BtfType::Array(_)
                | BtfType::Struct(_)
                | BtfType::Union(_)
                | BtfType::Enum(_)
                | BtfType::Fwd(_)
                | BtfType::Func(_)
                | BtfType::FuncProto(_)
                | BtfType::Var(_)
                | BtfType::Datasec(_)
                | BtfType::DeclTag(_) => return Ok(type_id),
            };
        }
    }
}
