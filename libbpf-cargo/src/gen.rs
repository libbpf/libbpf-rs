use std::collections::BTreeMap;
use std::ffi::c_void;
use std::ffi::{CStr, CString};
use std::fmt::Write as fmt_write;
use std::fs::File;
use std::io::Write;
use std::mem::size_of;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;

use anyhow::{bail, ensure, Result};
use scopeguard::defer;
use vsprintf::vsprintf;

use crate::metadata;
use crate::metadata::UnprocessedObj;

macro_rules! gen_bpf_object_iter {
    ($name:ident, $iter_ty:ty, $next_fn:expr) => {
        struct $name {
            obj: *mut libbpf_sys::bpf_object,
            last: *mut $iter_ty,
        }

        impl $name {
            fn new(obj: *mut libbpf_sys::bpf_object) -> $name {
                $name {
                    obj,
                    last: ptr::null_mut(),
                }
            }
        }

        impl Iterator for $name {
            type Item = *mut $iter_ty;

            fn next(&mut self) -> Option<Self::Item> {
                self.last = unsafe { $next_fn(self.last, self.obj) };

                if self.last.is_null() {
                    None
                } else {
                    Some(self.last)
                }
            }
        }
    };
}

gen_bpf_object_iter!(MapIter, libbpf_sys::bpf_map, libbpf_sys::bpf_map__next);
gen_bpf_object_iter!(
    ProgIter,
    libbpf_sys::bpf_program,
    libbpf_sys::bpf_program__next
);

struct BtfIter {
    btf: *const libbpf_sys::btf,
    i: u32,
    nr_types: u32,
}

impl BtfIter {
    fn new(obj: *mut libbpf_sys::bpf_object) -> Self {
        assert!(!obj.is_null());

        let btf = unsafe { libbpf_sys::bpf_object__btf(obj) };
        let nr_types = if btf.is_null() {
            0
        } else {
            unsafe { libbpf_sys::btf__get_nr_types(btf) }
        };

        BtfIter {
            btf,
            i: 1,
            nr_types,
        }
    }
}

impl Iterator for BtfIter {
    type Item = *const libbpf_sys::btf_type;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i > self.nr_types {
            return None;
        }

        let ty = unsafe { libbpf_sys::btf__type_by_id(self.btf, self.i) };
        // Will only be null if `i > nr_types`
        assert!(!ty.is_null());

        self.i += 1;

        Some(ty)
    }
}

fn btf_info_kind(ty: *const libbpf_sys::btf_type) -> Result<u32> {
    ensure!(!ty.is_null(), "ty is null");

    let info = unsafe { (*ty).info };

    Ok((info >> 24) & 0x0F)
}

fn btf_info_vlen(ty: *const libbpf_sys::btf_type) -> Result<u32> {
    ensure!(!ty.is_null(), "ty is null");

    let info = unsafe { (*ty).info };

    Ok(info & 0xFFFF)
}

#[repr(C)]
struct BtfVarSecinfo {
    ty: u32,
    offset: u32,
    size: u32,
}

fn btf_var_secinfos(ty: *const libbpf_sys::btf_type) -> Result<*const BtfVarSecinfo> {
    ensure!(!ty.is_null(), "ty is null");

    let ptr = unsafe { ty.offset(1) } as *const BtfVarSecinfo;

    Ok(ptr)
}

/// Run `rustfmt` over `s` and return result
fn rustfmt(s: &str) -> Result<String> {
    let mut cmd = Command::new("rustfmt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    write!(cmd.stdin.take().unwrap(), "{}", s)?;
    let output = cmd.wait_with_output()?;

    Ok(String::from_utf8(output.stdout)?)
}

fn capitalize_first_letter(s: &str) -> String {
    let mut ret = String::new();

    if s.is_empty() {
        return ret;
    }

    ret += &s.chars().next().unwrap().to_uppercase().to_string();
    if s.len() > 1 {
        ret += &s[1..];
    }

    ret
}

fn get_raw_map_name(map: *const libbpf_sys::bpf_map) -> Result<String> {
    let name_ptr = unsafe { libbpf_sys::bpf_map__name(map) };
    if name_ptr.is_null() {
        bail!("Map name unknown");
    }

    Ok(unsafe { CStr::from_ptr(name_ptr) }.to_str()?.to_string())
}

fn canonicalize_internal_map_name(s: &str) -> Result<String> {
    if s.ends_with(".data") {
        Ok("data".to_string())
    } else if s.ends_with(".rodata") {
        Ok("rodata".to_string())
    } else if s.ends_with(".bss") {
        Ok("bss".to_string())
    } else if s.ends_with(".kconfig") {
        Ok("kconfig".to_string())
    } else {
        bail!("Unknown map type: {}", s);
    }
}

/// Same as `get_raw_map_name` except the name is canonicalized
fn get_map_name(map: *const libbpf_sys::bpf_map) -> Result<String> {
    let name = get_raw_map_name(map)?;

    if unsafe { !libbpf_sys::bpf_map__is_internal(map) } {
        Ok(name)
    } else {
        canonicalize_internal_map_name(&name)
    }
}

fn get_prog_name(prog: *const libbpf_sys::bpf_program) -> Result<String> {
    let name_ptr = unsafe { libbpf_sys::bpf_program__name(prog) };

    if name_ptr.is_null() {
        bail!("Prog name unknown");
    }

    Ok(unsafe { CStr::from_ptr(name_ptr) }.to_str()?.to_string())
}

fn map_is_mmapable(map: *const libbpf_sys::bpf_map) -> bool {
    let internal = unsafe { libbpf_sys::bpf_map__is_internal(map) };
    let def = unsafe { libbpf_sys::bpf_map__def(map) };
    let mmapable = unsafe { (*def).map_flags } & libbpf_sys::BPF_F_MMAPABLE;

    internal && (mmapable > 0)
}

fn gen_skel_c_skel_constructor(
    skel: &mut String,
    object: *mut libbpf_sys::bpf_object,
    name: &str,
) -> Result<()> {
    write!(
        skel,
        r#"
        fn build_skel_config() -> libbpf_rs::Result<libbpf_rs::skeleton::ObjectSkeletonConfig<'static>>
        {{
            let mut builder = libbpf_rs::skeleton::ObjectSkeletonConfigBuilder::new(DATA);
            builder
                .name("{name}_bpf")
        "#,
        name = name
    )?;

    for map in MapIter::new(object) {
        let raw_name = get_raw_map_name(map)?;
        let mmaped = if map_is_mmapable(map) {
            "true"
        } else {
            "false"
        };

        write!(
            skel,
            r#"
            .map("{raw_name}", {mmaped})
            "#,
            raw_name = raw_name,
            mmaped = mmaped,
        )?;
    }

    for prog in ProgIter::new(object) {
        let name = get_prog_name(prog)?;

        write!(
            skel,
            r#"
            .prog("{name}")
            "#,
            name = name,
        )?;
    }

    writeln!(skel, ";")?;

    write!(
        skel,
        r#"
            builder.build()
        }}
        "#
    )?;

    Ok(())
}

fn gen_skel_map_defs(
    skel: &mut String,
    object: *mut libbpf_sys::bpf_object,
    obj_name: &str,
    open: bool,
) -> Result<()> {
    if MapIter::new(object).next().is_none() {
        return Ok(());
    }

    let (struct_name, inner_ty, return_ty) = if open {
        (
            format!("Open{}Maps", obj_name),
            "libbpf_rs::OpenObject",
            "libbpf_rs::OpenMap",
        )
    } else {
        (
            format!("{}Maps", obj_name),
            "libbpf_rs::Object",
            "libbpf_rs::Map",
        )
    };

    write!(
        skel,
        r#"
        pub struct {struct_name}<'a> {{
            inner: &'a mut {inner_ty},
        }}

        impl<'a> {struct_name}<'a> {{
        "#,
        inner_ty = inner_ty,
        struct_name = struct_name
    )?;

    for map in MapIter::new(object) {
        write!(
            skel,
            r#"
            pub fn {map_name}(&mut self) -> &mut {return_ty} {{
                self.inner.map_unwrap("{raw_map_name}")
            }}
            "#,
            map_name = get_map_name(map)?,
            raw_map_name = get_raw_map_name(map)?,
            return_ty = return_ty,
        )?;
    }

    writeln!(skel, "}}")?;

    Ok(())
}

fn gen_skel_prog_defs(
    skel: &mut String,
    object: *mut libbpf_sys::bpf_object,
    obj_name: &str,
    open: bool,
) -> Result<()> {
    if ProgIter::new(object).next().is_none() {
        return Ok(());
    }

    let (struct_name, inner_ty, return_ty) = if open {
        (
            format!("Open{}Progs", obj_name),
            "libbpf_rs::OpenObject",
            "libbpf_rs::OpenProgram",
        )
    } else {
        (
            format!("{}Progs", obj_name),
            "libbpf_rs::Object",
            "libbpf_rs::Program",
        )
    };

    write!(
        skel,
        r#"
        pub struct {struct_name}<'a> {{
            inner: &'a mut {inner_ty},
        }}

        impl<'a> {struct_name}<'a> {{
        "#,
        inner_ty = inner_ty,
        struct_name = struct_name
    )?;

    for prog in ProgIter::new(object) {
        write!(
            skel,
            r#"
            pub fn {prog_name}(&mut self) -> &mut {return_ty} {{
                self.inner.prog_unwrap("{prog_name}")
            }}
            "#,
            prog_name = get_prog_name(prog)?,
            return_ty = return_ty,
        )?;
    }

    writeln!(skel, "}}")?;

    Ok(())
}

unsafe extern "C" fn dump_printer(
    ctx: *mut c_void,
    fmt: *const c_char,
    args: *mut libbpf_sys::__va_list_tag,
) {
    let buf = &mut *(ctx as *mut String);

    match vsprintf(fmt, args) {
        Ok(d) => buf.push_str(&d),
        Err(e) => panic!("Failed to vsprintf btf type: {}", e),
    };
}

fn c_to_rust(c: &str) -> Result<String> {
    let bindings = bindgen::Builder::default()
        .header_contents("input.h", c)
        .disable_header_comment()
        .layout_tests(false)
        .generate();

    match bindings {
        Ok(b) => Ok(b.to_string()),
        Err(_) => bail!("Failed to generate rust bindings to datasec variables"),
    }
}

fn gen_skel_one_datasec_def(
    skel: &mut String,
    btf: *const libbpf_sys::btf,
    sec: *const libbpf_sys::btf_type,
    obj_name: &str,
    debug: bool,
) -> Result<()> {
    // Setup libbpf BTF dumper
    let mut buf = String::new();
    let buf_ptr: *mut String = &mut buf;
    let mut dump_opts = libbpf_sys::btf_dump_opts::default();
    dump_opts.ctx = buf_ptr as *mut c_void;
    let dump =
        unsafe { libbpf_sys::btf_dump__new(btf, ptr::null(), &dump_opts, Some(dump_printer)) };
    if unsafe { libbpf_sys::libbpf_get_error(dump as *const _) } != 0 {
        bail!("Failed to create struct bpf_dump");
    }
    defer! {
        unsafe { libbpf_sys::btf_dump__free(dump) };
    }

    let sec_name =
        unsafe { CStr::from_ptr(libbpf_sys::btf__name_by_offset(btf, (*sec).name_off)).to_str()? };
    let sec_ident = match canonicalize_internal_map_name(sec_name) {
        Ok(n) => capitalize_first_letter(&n),
        // Not a datasection we can generate definitions for
        Err(_) => return Ok(()),
    };

    writeln!(
        buf,
        r#"struct {obj_name}{sec_name} {{"#,
        obj_name = obj_name,
        sec_name = sec_ident,
    )?;

    let mut sec_var = btf_var_secinfos(sec)?;
    let mut offset: u32 = 0;
    for _ in 0..btf_info_vlen(sec)? {
        let var = unsafe { libbpf_sys::btf__type_by_id(btf, (*sec_var).ty) };
        let var_name =
            unsafe { CStr::from_ptr(libbpf_sys::btf__name_by_offset(btf, (*var).name_off)) };

        // Where BTF tells us the var offset needs to be
        let needed_offset = unsafe { (*sec_var).offset };
        if offset > needed_offset {
            bail!(
                "Invalid var={}, offset={} > needed_offset={}",
                var_name.to_string_lossy(),
                offset,
                needed_offset
            );
        }

        // Get alignment of var
        let align_signed = unsafe { libbpf_sys::btf__align_of(btf, (*var).__bindgen_anon_1.type_) };
        if align_signed <= 0 {
            bail!(
                "Failed to determine alignment of var={}",
                var_name.to_string_lossy()
            );
        }
        let mut align = align_signed as u32;

        // Assume 32-bit alignment in case we're generating code for 32-bit
        // arch. Worst case is on a 64-bit arch the compiler will generate
        // extra padding. The final layout will still be identical to what is
        // described by BTF.
        if align > 4 {
            align = 4;
        }

        // Round `offset` _up_ to nearest multiple of `align`
        let aligned_offset = (offset + align - 1) / align * align;

        // If we aren't naturally aligning to the right offset, insert padding to the right offset
        if aligned_offset != needed_offset {
            writeln!(buf, r#"char __pad_{}[{}]"#, offset, needed_offset - offset)?;
        }

        // Dump current field
        //
        // NB: create through `default()` to ensure the trailing padding is zero'd. If non-zero,
        // libbpf will complain.
        let mut emit_opts = libbpf_sys::btf_dump_emit_type_decl_opts::default();
        emit_opts.sz = size_of::<libbpf_sys::btf_dump_emit_type_decl_opts>() as u64;
        emit_opts.field_name = var_name.as_ptr();
        emit_opts.indent_level = 1;
        emit_opts.strip_mods = true;
        if unsafe {
            libbpf_sys::btf_dump__emit_type_decl(dump, (*var).__bindgen_anon_1.type_, &emit_opts)
        } != 0
        {
            bail!(
                "Failed to dump type decl for var={}",
                var_name.to_string_lossy()
            );
        }
        writeln!(buf, ";")?;

        // Set `offset` to end of current var
        offset = unsafe { (*sec_var).offset + (*sec_var).size };

        // Go to next var in section
        sec_var = unsafe { sec_var.offset(1) };
    }

    writeln!(buf, "}};")?;

    if debug {
        println!("Datasec C struct:\n{}", buf);
    }

    let rust_defs = c_to_rust(&buf)?;
    write!(skel, "\n{}", rust_defs)?;

    Ok(())
}

fn gen_skel_datasec_defs(
    skel: &mut String,
    object: *mut libbpf_sys::bpf_object,
    obj_name: &str,
    debug: bool,
) -> Result<()> {
    let btf = unsafe { libbpf_sys::bpf_object__btf(object) };

    for ty in BtfIter::new(object) {
        if btf_info_kind(ty)? != libbpf_sys::BTF_KIND_DATASEC {
            continue;
        }

        gen_skel_one_datasec_def(skel, btf, ty, obj_name, debug)?;
    }

    Ok(())
}

fn gen_skel_map_getter(
    skel: &mut String,
    object: *mut libbpf_sys::bpf_object,
    obj_name: &str,
    open: bool,
) -> Result<()> {
    if MapIter::new(object).next().is_none() {
        return Ok(());
    }

    let return_ty = if open {
        format!("Open{}Maps", obj_name)
    } else {
        format!("{}Maps", obj_name)
    };

    write!(
        skel,
        r#"
        pub fn maps(&mut self) -> {return_ty} {{
            {return_ty} {{
                inner: &mut self.obj,
            }}
        }}
        "#,
        return_ty = return_ty
    )?;

    Ok(())
}

fn gen_skel_prog_getter(
    skel: &mut String,
    object: *mut libbpf_sys::bpf_object,
    obj_name: &str,
    open: bool,
) -> Result<()> {
    if ProgIter::new(object).next().is_none() {
        return Ok(());
    }

    let return_ty = if open {
        format!("Open{}Progs", obj_name)
    } else {
        format!("{}Progs", obj_name)
    };

    write!(
        skel,
        r#"
        pub fn progs(&mut self) -> {return_ty} {{
            {return_ty} {{
                inner: &mut self.obj,
            }}
        }}
        "#,
        return_ty = return_ty
    )?;

    Ok(())
}

fn gen_skel_link_defs(
    skel: &mut String,
    object: *mut libbpf_sys::bpf_object,
    obj_name: &str,
) -> Result<()> {
    if ProgIter::new(object).next().is_none() {
        return Ok(());
    }

    write!(
        skel,
        r#"
        #[derive(Default)]
        pub struct {}Links {{
        "#,
        obj_name
    )?;

    for prog in ProgIter::new(object) {
        write!(
            skel,
            r#"pub {}: Option<libbpf_rs::Link>,
            "#,
            get_prog_name(prog)?
        )?;
    }

    writeln!(skel, "}}")?;

    Ok(())
}

fn gen_skel_link_getter(
    skel: &mut String,
    object: *mut libbpf_sys::bpf_object,
    obj_name: &str,
) -> Result<()> {
    if ProgIter::new(object).next().is_none() {
        return Ok(());
    }

    write!(
        skel,
        r#"pub links: {}Links,
        "#,
        obj_name
    )?;

    Ok(())
}

fn open_object_file(path: &Path) -> Result<*mut libbpf_sys::bpf_object> {
    if !path.exists() {
        bail!("Object file not found: {}", path.display());
    }
    let path_cstring = CString::new(path.to_string_lossy().into_owned())?;
    let mut obj_opts = libbpf_sys::bpf_object_open_opts::default();
    obj_opts.sz = std::mem::size_of::<libbpf_sys::bpf_object_open_opts>() as libbpf_sys::size_t;
    let object = unsafe { libbpf_sys::bpf_object__open_file(path_cstring.as_ptr(), &obj_opts) };
    if object.is_null() {
        bail!("Could not open object file={}", path.display());
    }

    Ok(object)
}

fn gen_skel_attach(
    skel: &mut String,
    object: *mut libbpf_sys::bpf_object,
    obj_name: &str,
) -> Result<()> {
    if ProgIter::new(object).next().is_none() {
        return Ok(());
    }

    write!(
        skel,
        r#"
        pub fn attach(&mut self) -> libbpf_rs::Result<()> {{
            let ret = unsafe {{ libbpf_sys::bpf_object__attach_skeleton(self.skel_config.get()) }};
            if ret != 0 {{
                return Err(libbpf_rs::Error::System(-ret));
            }}

            self.links = {}Links {{
        "#,
        obj_name
    )?;

    for (idx, prog) in ProgIter::new(object).enumerate() {
        let prog_name = get_prog_name(prog)?;

        write!(
            skel,
            r#"{prog_name}: (|| {{
                let ptr = self.skel_config.prog_link_ptr({idx})?;
                if ptr.is_null() {{
                    Ok(None)
                }} else {{
                    Ok(Some(unsafe {{ libbpf_rs::Link::from_ptr(ptr) }}))
                }}
            }})()?,
            "#,
            prog_name = prog_name,
            idx = idx,
        )?;
    }

    write!(
        skel,
        r#"
            }};

            Ok(())
        }}
        "#,
    )?;

    Ok(())
}

/// Generate contents of a single skeleton
fn gen_skel_contents(debug: bool, obj: &UnprocessedObj) -> Result<String> {
    let mut skel = String::new();

    write!(
        skel,
        r#"// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
           //
           // THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

           use libbpf_rs::libbpf_sys;
        "#
    )?;

    let mut obj_file_path = obj.out.clone();
    obj_file_path.push(format!("{}.bpf.o", obj.name));

    write!(
        skel,
        r#"
        const DATA: &[u8] = include_bytes!("{}");
        "#,
        obj_file_path.as_path().display()
    )?;

    // Open bpf_object so we can iterate over maps and progs
    let object = open_object_file(obj_file_path.as_path())?;
    let obj_name = capitalize_first_letter(&obj.name);

    gen_skel_c_skel_constructor(&mut skel, object, &obj.name)?;

    write!(
        skel,
        r#"
        #[derive(Default)]
        pub struct {name}SkelBuilder {{
            pub obj_builder: libbpf_rs::ObjectBuilder,
        }}

        impl {name}SkelBuilder {{
            pub fn open(&mut self) -> libbpf_rs::Result<Open{name}Skel> {{
                let mut skel_config = build_skel_config()?;
                let open_opts = self.obj_builder.opts(std::ptr::null());

                let ret = unsafe {{ libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) }};
                if ret != 0 {{
                    return Err(libbpf_rs::Error::System(-ret));
                }}

                let obj = unsafe {{ libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr()) }};

                Ok(Open{name}Skel {{
                    obj,
                    skel_config
                }})
            }}
        }}
        "#,
        name = obj_name
    )?;

    gen_skel_map_defs(&mut skel, object, &obj_name, true)?;
    gen_skel_prog_defs(&mut skel, object, &obj_name, true)?;
    gen_skel_datasec_defs(&mut skel, object, &obj_name, debug)?;

    write!(
        skel,
        r#"
        pub struct Open{name}Skel<'a> {{
            pub obj: libbpf_rs::OpenObject,
            skel_config: libbpf_rs::skeleton::ObjectSkeletonConfig<'a>,
        }}

        impl<'a> Open{name}Skel<'a> {{
            pub fn load(mut self) -> libbpf_rs::Result<{name}Skel<'a>> {{
                let ret = unsafe {{ libbpf_sys::bpf_object__load_skeleton(self.skel_config.get()) }};
                if ret != 0 {{
                    return Err(libbpf_rs::Error::System(-ret));
                }}

                let obj = unsafe {{ libbpf_rs::Object::from_ptr(self.obj.take_ptr()) }};

                Ok({name}Skel {{
                    obj,
                    skel_config: self.skel_config,
                    {links}
                }})
            }}
        "#,
        name = &obj_name,
        links = if ProgIter::new(object).next().is_some() {
            format!(r#"links: {}Links::default()"#, obj_name)
        } else {
            "".to_string()
        }
    )?;
    gen_skel_prog_getter(&mut skel, object, &obj_name, true)?;
    gen_skel_map_getter(&mut skel, object, &obj_name, true)?;
    writeln!(skel, "}}")?;

    gen_skel_map_defs(&mut skel, object, &obj_name, false)?;
    gen_skel_prog_defs(&mut skel, object, &obj_name, false)?;
    gen_skel_link_defs(&mut skel, object, &obj_name)?;

    write!(
        skel,
        r#"
        pub struct {name}Skel<'a> {{
            pub obj: libbpf_rs::Object,
            skel_config: libbpf_rs::skeleton::ObjectSkeletonConfig<'a>,
        "#,
        name = &obj_name,
    )?;
    gen_skel_link_getter(&mut skel, object, &obj_name)?;
    write!(
        skel,
        r#"
        }}

        impl<'a> {name}Skel<'a> {{
        "#,
        name = &obj_name,
    )?;
    gen_skel_prog_getter(&mut skel, object, &obj_name, false)?;
    gen_skel_map_getter(&mut skel, object, &obj_name, false)?;
    gen_skel_attach(&mut skel, object, &obj_name)?;
    writeln!(skel, "}}")?;

    Ok(skel)
}

/// Write a single skeleton to disk
fn gen_skel(debug: bool, obj: &UnprocessedObj) -> Result<()> {
    if obj.name.is_empty() {
        bail!("Object file has no name");
    }

    let skel = rustfmt(&gen_skel_contents(debug, obj)?)?;

    let mut path = obj.path.clone();
    path.pop();
    path.push(format!("{}.skel.rs", obj.name));
    let mut file = File::create(path)?;
    file.write_all(skel.as_bytes())?;

    Ok(())
}

/// Generate mod.rs in src/bpf directory of each project.
///
/// Each `UnprocessedObj` in `objs` must belong to same project.
pub fn gen_mods(objs: &[UnprocessedObj]) -> Result<()> {
    if objs.is_empty() {
        return Ok(());
    }

    let mut path = objs[0].path.clone();
    path.pop();
    path.push("mod.rs");

    let mut contents = String::new();
    write!(
        contents,
        r#"
        // SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)"
        //
        // THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

        #[allow(dead_code)]
        #[allow(non_snake_case)]

        "#
    )?;

    for obj in objs {
        write!(
            contents,
            r#"
            #[path = "{name}.skel.rs"]
            mod {name}_skel;
            "#,
            name = obj.name
        )?;
    }

    for obj in objs {
        write!(
            contents,
            r#"
            pub use {}_skel::*;
            "#,
            obj.name
        )?;
    }

    let mut file = File::create(path)?;
    file.write_all(rustfmt(&contents)?.as_bytes())?;

    Ok(())
}

pub fn gen(debug: bool, manifest_path: Option<&PathBuf>) -> i32 {
    let to_gen = match metadata::get(debug, manifest_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e);
            return 1;
        }
    };

    if debug && !to_gen.is_empty() {
        println!("Found bpf objs to gen skel:");
        for obj in &to_gen {
            println!("\t{:?}", obj);
        }
    } else if to_gen.is_empty() {
        eprintln!("Did not find any bpf objects to generate skeleton");
        return 1;
    }

    // Map to store package_name -> [UnprocessedObj]
    let mut package_objs: BTreeMap<String, Vec<UnprocessedObj>> = BTreeMap::new();

    for obj in to_gen {
        match gen_skel(debug, &obj) {
            Ok(_) => (),
            Err(e) => {
                eprintln!(
                    "Failed to generate skeleton for {}: {}",
                    obj.path.as_path().display(),
                    e
                );
                return 1;
            }
        }

        match package_objs.get_mut(&obj.package) {
            Some(v) => v.push(obj.clone()),
            None => {
                package_objs.insert(obj.package.clone(), vec![obj.clone()]);
            }
        };
    }

    for (package, objs) in package_objs {
        match gen_mods(&objs) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to generate mod.rs for package={}: {}", package, e);
                return 1;
            }
        }
    }

    0
}
