use std::collections::BTreeMap;
use std::convert::TryInto;
use std::ffi::{c_void, CStr, CString};
use std::fmt::Write as fmt_write;
use std::fs::File;
use std::io::Write;
use std::os::raw::c_ulong;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;

use anyhow::{bail, ensure, Context, Result};
use memmap2::Mmap;

use crate::btf;
use crate::metadata;
use crate::metadata::UnprocessedObj;

#[repr(transparent)]
pub(crate) struct BpfObj(ptr::NonNull<libbpf_sys::bpf_object>);

impl BpfObj {
    pub fn new(object: ptr::NonNull<libbpf_sys::bpf_object>) -> BpfObj {
        Self(object)
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut libbpf_sys::bpf_object {
        self.0.as_ptr()
    }
}

impl Drop for BpfObj {
    fn drop(&mut self) {
        unsafe { libbpf_sys::bpf_object__close(self.as_mut_ptr()) }
    }
}

pub enum OutputDest<'a> {
    Stdout,
    /// Infer a filename and place file in specified directory
    Directory(&'a Path),
    #[allow(dead_code)]
    /// File to place output in
    // Only constructed in libbpf-cargo library
    File(&'a Path),
}

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
                self.last = unsafe { $next_fn(self.obj, self.last) };

                if self.last.is_null() {
                    None
                } else {
                    Some(self.last)
                }
            }
        }
    };
}

gen_bpf_object_iter!(
    MapIter,
    libbpf_sys::bpf_map,
    libbpf_sys::bpf_object__next_map
);
gen_bpf_object_iter!(
    ProgIter,
    libbpf_sys::bpf_program,
    libbpf_sys::bpf_object__next_program
);

/// Run `rustfmt` over `s` and return result
fn rustfmt(s: &str, rustfmt_path: Option<&PathBuf>) -> Result<String> {
    let mut cmd = if let Some(r) = rustfmt_path {
        Command::new(r)
    } else {
        Command::new("rustfmt")
    }
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .spawn()
    .context("Failed to spawn rustfmt")?;

    // Send input in via stdin
    write!(cmd.stdin.take().unwrap(), "{}", s)?;

    // Extract output
    let output = cmd
        .wait_with_output()
        .context("Failed to execute rustfmt")?;
    ensure!(
        output.status.success(),
        "Failed to rustfmt: {}",
        output.status
    );

    Ok(String::from_utf8(output.stdout)?)
}

fn capitalize_first_letter(s: &str) -> String {
    if s.is_empty() {
        return "".to_string();
    }

    s.split('_').fold(String::new(), |mut acc, ts| {
        acc += &ts.chars().next().unwrap().to_uppercase().to_string();
        if ts.len() > 1 {
            acc += &ts[1..];
        }
        acc
    })
}

fn get_raw_map_name(map: *const libbpf_sys::bpf_map) -> Result<String> {
    let name_ptr = unsafe { libbpf_sys::bpf_map__name(map) };
    if name_ptr.is_null() {
        bail!("Map name unknown");
    }

    Ok(unsafe { CStr::from_ptr(name_ptr) }.to_str()?.to_string())
}

fn canonicalize_internal_map_name(s: &str) -> Option<String> {
    if s.ends_with(".data") {
        Some("data".to_string())
    } else if s.ends_with(".rodata") {
        Some("rodata".to_string())
    } else if s.ends_with(".bss") {
        Some("bss".to_string())
    } else if s.ends_with(".kconfig") {
        Some("kconfig".to_string())
    } else {
        eprintln!("Warning: unrecognized map: {}", s);
        None
    }
}

/// Same as `get_raw_map_name` except the name is canonicalized
fn get_map_name(map: *const libbpf_sys::bpf_map) -> Result<Option<String>> {
    let name = get_raw_map_name(map)?;

    if unsafe { !libbpf_sys::bpf_map__is_internal(map) } {
        Ok(Some(name))
    } else {
        Ok(canonicalize_internal_map_name(&name))
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
    (unsafe { libbpf_sys::bpf_map__map_flags(map) } & libbpf_sys::BPF_F_MMAPABLE) > 0
}

fn map_is_datasec(map: *const libbpf_sys::bpf_map) -> bool {
    let internal = unsafe { libbpf_sys::bpf_map__is_internal(map) };
    let mmapable = map_is_mmapable(map);

    internal && mmapable
}

fn map_is_readonly(map: *const libbpf_sys::bpf_map) -> bool {
    assert!(map_is_mmapable(map));

    // BPF_F_RDONLY_PROG means readonly from prog side
    (unsafe { libbpf_sys::bpf_map__map_flags(map) } & libbpf_sys::BPF_F_RDONLY_PROG) > 0
}

fn gen_skel_c_skel_constructor(skel: &mut String, object: &mut BpfObj, name: &str) -> Result<()> {
    write!(
        skel,
        r#"
        fn build_skel_config() -> libbpf_rs::Result<libbpf_rs::skeleton::ObjectSkeletonConfig<'static>>
        {{
            let mut builder = libbpf_rs::skeleton::ObjectSkeletonConfigBuilder::new(DATA);
            builder
                .name("{name}")
        "#,
        name = name
    )?;

    for map in MapIter::new(object.as_mut_ptr()) {
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

    for prog in ProgIter::new(object.as_mut_ptr()) {
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
    object: &mut BpfObj,
    obj_name: &str,
    open: bool,
    mutable: bool,
) -> Result<()> {
    if MapIter::new(object.as_mut_ptr()).next().is_none() {
        return Ok(());
    }

    let (struct_suffix, mut_prefix, map_fn) = if mutable {
        ("Mut", "mut ", "map_mut")
    } else {
        ("", "", "map")
    };

    let (struct_name, inner_ty, return_ty) = if open {
        (
            format!("Open{}Maps{}", obj_name, struct_suffix),
            "libbpf_rs::OpenObject",
            "libbpf_rs::OpenMap",
        )
    } else {
        (
            format!("{}Maps{}", obj_name, struct_suffix),
            "libbpf_rs::Object",
            "libbpf_rs::Map",
        )
    };

    write!(
        skel,
        r#"
        pub struct {struct_name}<'a> {{
            inner: &'a {mut_prefix}{inner_ty},
        }}

        impl<'a> {struct_name}<'a> {{
        "#,
        inner_ty = inner_ty,
        struct_name = struct_name,
        mut_prefix = mut_prefix,
    )?;

    for map in MapIter::new(object.as_mut_ptr()) {
        let map_name = match get_map_name(map)? {
            Some(n) => n,
            None => continue,
        };

        write!(
            skel,
            r#"
            pub fn {map_name}(&{mut_prefix}self) -> &{mut_prefix}{return_ty} {{
                self.inner.{map_fn}("{raw_map_name}").unwrap()
            }}
            "#,
            map_name = map_name,
            raw_map_name = get_raw_map_name(map)?,
            return_ty = return_ty,
            mut_prefix = mut_prefix,
            map_fn = map_fn
        )?;
    }

    writeln!(skel, "}}")?;

    Ok(())
}

fn gen_skel_prog_defs(
    skel: &mut String,
    object: &mut BpfObj,
    obj_name: &str,
    open: bool,
    mutable: bool,
) -> Result<()> {
    if ProgIter::new(object.as_mut_ptr()).next().is_none() {
        return Ok(());
    }

    let (struct_suffix, mut_prefix, prog_fn) = if mutable {
        ("Mut", "mut ", "prog_mut")
    } else {
        ("", "", "prog")
    };

    let (struct_name, inner_ty, return_ty) = if open {
        (
            format!("Open{}Progs{}", obj_name, struct_suffix),
            "libbpf_rs::OpenObject",
            "libbpf_rs::OpenProgram",
        )
    } else {
        (
            format!("{}Progs{}", obj_name, struct_suffix),
            "libbpf_rs::Object",
            "libbpf_rs::Program",
        )
    };

    write!(
        skel,
        r#"
        pub struct {struct_name}<'a> {{
            inner: &'a {mut_prefix}{inner_ty},
        }}

        impl<'a> {struct_name}<'a> {{
        "#,
        inner_ty = inner_ty,
        struct_name = struct_name,
        mut_prefix = mut_prefix,
    )?;

    for prog in ProgIter::new(object.as_mut_ptr()) {
        write!(
            skel,
            r#"
            pub fn {prog_name}(&{mut_prefix}self) -> &{mut_prefix}{return_ty} {{
                self.inner.{prog_fn}("{prog_name}").unwrap()
            }}
            "#,
            prog_name = get_prog_name(prog)?,
            return_ty = return_ty,
            mut_prefix = mut_prefix,
            prog_fn = prog_fn
        )?;
    }

    writeln!(skel, "}}")?;

    Ok(())
}

fn gen_skel_datasec_defs(skel: &mut String, obj_name: &str, object: &[u8]) -> Result<()> {
    let btf = match btf::Btf::new(obj_name, object)? {
        Some(b) => b,
        None => return Ok(()),
    };

    for (idx, ty) in btf.types().iter().enumerate() {
        if let btf::BtfType::Datasec(d) = ty {
            let sec_ident = match canonicalize_internal_map_name(d.name) {
                Some(n) => n,
                None => continue,
            };

            write!(
                skel,
                r#"
                pub mod {}_{}_types {{
                "#,
                obj_name, sec_ident,
            )?;

            let sec_def = btf.type_definition(idx.try_into().unwrap())?;
            write!(skel, "{}", sec_def)?;

            writeln!(skel, "}}")?;
        }
    }

    Ok(())
}

fn gen_skel_map_getter(
    skel: &mut String,
    object: &mut BpfObj,
    obj_name: &str,
    open: bool,
    mutable: bool,
) -> Result<()> {
    if MapIter::new(object.as_mut_ptr()).next().is_none() {
        return Ok(());
    }

    let (struct_suffix, mut_prefix, map_fn) = if mutable {
        ("Mut", "mut ", "maps_mut")
    } else {
        ("", "", "maps")
    };

    let return_ty = if open {
        format!("Open{}Maps{}", obj_name, struct_suffix)
    } else {
        format!("{}Maps{}", obj_name, struct_suffix)
    };

    write!(
        skel,
        r#"
        pub fn {map_fn}(&{mut_prefix}self) -> {return_ty} {{
            {return_ty} {{
                inner: &{mut_prefix}self.obj,
            }}
        }}
        "#,
        return_ty = return_ty,
        map_fn = map_fn,
        mut_prefix = mut_prefix,
    )?;

    Ok(())
}

fn gen_skel_prog_getter(
    skel: &mut String,
    object: &mut BpfObj,
    obj_name: &str,
    open: bool,
    mutable: bool,
) -> Result<()> {
    if ProgIter::new(object.as_mut_ptr()).next().is_none() {
        return Ok(());
    }

    let (struct_suffix, mut_prefix, prog_fn) = if mutable {
        ("Mut", "mut ", "progs_mut")
    } else {
        ("", "", "progs")
    };

    let return_ty = if open {
        format!("Open{}Progs{}", obj_name, struct_suffix)
    } else {
        format!("{}Progs{}", obj_name, struct_suffix)
    };

    write!(
        skel,
        r#"
        pub fn {prog_fn}(&{mut_prefix}self) -> {return_ty} {{
            {return_ty} {{
                inner: &{mut_prefix}self.obj,
            }}
        }}
        "#,
        return_ty = return_ty,
        mut_prefix = mut_prefix,
        prog_fn = prog_fn,
    )?;

    Ok(())
}

fn gen_skel_datasec_getters(
    skel: &mut String,
    object: &mut BpfObj,
    obj_name: &str,
    loaded: bool,
) -> Result<()> {
    for (idx, map) in MapIter::new(object.as_mut_ptr()).enumerate() {
        if !map_is_datasec(map) {
            continue;
        }

        let name = match get_map_name(map)? {
            Some(n) => n,
            None => continue,
        };
        let struct_name = format!(
            "{obj_name}_{name}_types::{name}",
            obj_name = obj_name,
            name = name,
        );
        let mutability = if loaded && map_is_readonly(map) {
            ""
        } else {
            "mut"
        };

        write!(
            skel,
            r#"
            pub fn {name}(&mut self) -> &'a {mut} {struct_name} {{
                unsafe {{
                    std::mem::transmute::<*mut std::ffi::c_void, &'a {mut} {struct_name}>(
                        self.skel_config.map_mmap_ptr({idx}).unwrap()
                    )
                }}
            }}
            "#,
            name = name,
            struct_name = struct_name,
            mut = mutability,
            idx = idx,
        )?;
    }

    Ok(())
}

fn gen_skel_link_defs(skel: &mut String, object: &mut BpfObj, obj_name: &str) -> Result<()> {
    if ProgIter::new(object.as_mut_ptr()).next().is_none() {
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

    for prog in ProgIter::new(object.as_mut_ptr()) {
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

fn gen_skel_link_getter(skel: &mut String, object: &mut BpfObj, obj_name: &str) -> Result<()> {
    if ProgIter::new(object.as_mut_ptr()).next().is_none() {
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

fn open_bpf_object(name: &str, data: &[u8]) -> Result<BpfObj> {
    let cname = CString::new(name)?;
    let obj_opts = libbpf_sys::bpf_object_open_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_object_open_opts>() as libbpf_sys::size_t,
        object_name: cname.as_ptr(),
        ..Default::default()
    };
    let object = unsafe {
        libbpf_sys::bpf_object__open_mem(
            data.as_ptr() as *const c_void,
            data.len() as c_ulong,
            &obj_opts,
        )
    };
    if object.is_null() {
        bail!("Failed to bpf_object__open_mem()");
    }

    Ok(BpfObj(ptr::NonNull::new(object).unwrap()))
}

fn gen_skel_attach(skel: &mut String, object: &mut BpfObj, obj_name: &str) -> Result<()> {
    if ProgIter::new(object.as_mut_ptr()).next().is_none() {
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

    for (idx, prog) in ProgIter::new(object.as_mut_ptr()).enumerate() {
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
fn gen_skel_contents(_debug: bool, raw_obj_name: &str, obj_file_path: &Path) -> Result<String> {
    let mut skel = String::new();

    write!(
        skel,
        r#"// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
           //
           // THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

           pub use self::imp::*;

           #[allow(dead_code)]
           #[allow(non_snake_case)]
           #[allow(non_camel_case_types)]
           #[allow(clippy::transmute_ptr_to_ref)]
           #[allow(clippy::upper_case_acronyms)]
           mod imp {{
           use libbpf_rs::libbpf_sys;
        "#
    )?;

    // The name we'll always hand to libbpf
    //
    // Note it's important this remains consistent b/c libbpf infers map/prog names from this name
    let libbpf_obj_name = format!("{}_bpf", raw_obj_name);
    // We'll use `obj_name` as the rust-ified object name
    let obj_name = capitalize_first_letter(raw_obj_name);

    // Open bpf_object so we can iterate over maps and progs
    let file = File::open(obj_file_path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let mut object = open_bpf_object(&libbpf_obj_name, &mmap)?;

    gen_skel_c_skel_constructor(&mut skel, &mut object, &libbpf_obj_name)?;

    write!(
        skel,
        r#"
        #[derive(Default)]
        pub struct {name}SkelBuilder {{
            pub obj_builder: libbpf_rs::ObjectBuilder,
        }}

        impl<'a> {name}SkelBuilder {{
            pub fn open(mut self) -> libbpf_rs::Result<Open{name}Skel<'a>> {{
                let mut skel_config = build_skel_config()?;
                let open_opts = self.obj_builder.opts(std::ptr::null());

                let ret = unsafe {{ libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) }};
                if ret != 0 {{
                    return Err(libbpf_rs::Error::System(-ret));
                }}

                let obj = unsafe {{ libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? }};

                Ok(Open{name}Skel {{
                    obj,
                    skel_config
                }})
            }}

            pub fn open_opts(self, open_opts: libbpf_sys::bpf_object_open_opts) -> libbpf_rs::Result<Open{name}Skel<'a>> {{
                let mut skel_config = build_skel_config()?;

                let ret = unsafe {{ libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) }};
                if ret != 0 {{
                    return Err(libbpf_rs::Error::System(-ret));
                }}

                let obj = unsafe {{ libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? }};

                Ok(Open{name}Skel {{
                    obj,
                    skel_config
                }})
            }}
        }}
        "#,
        name = obj_name
    )?;

    gen_skel_map_defs(&mut skel, &mut object, &obj_name, true, false)?;
    gen_skel_map_defs(&mut skel, &mut object, &obj_name, true, true)?;
    gen_skel_prog_defs(&mut skel, &mut object, &obj_name, true, false)?;
    gen_skel_prog_defs(&mut skel, &mut object, &obj_name, true, true)?;
    gen_skel_datasec_defs(&mut skel, raw_obj_name, &mmap)?;

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

                let obj = unsafe {{ libbpf_rs::Object::from_ptr(self.obj.take_ptr())? }};

                Ok({name}Skel {{
                    obj,
                    skel_config: self.skel_config,
                    {links}
                }})
            }}
        "#,
        name = &obj_name,
        links = if ProgIter::new(object.as_mut_ptr()).next().is_some() {
            format!(r#"links: {}Links::default()"#, obj_name)
        } else {
            "".to_string()
        }
    )?;
    gen_skel_prog_getter(&mut skel, &mut object, &obj_name, true, false)?;
    gen_skel_prog_getter(&mut skel, &mut object, &obj_name, true, true)?;
    gen_skel_map_getter(&mut skel, &mut object, &obj_name, true, false)?;
    gen_skel_map_getter(&mut skel, &mut object, &obj_name, true, true)?;
    gen_skel_datasec_getters(&mut skel, &mut object, raw_obj_name, false)?;
    writeln!(skel, "}}")?;

    gen_skel_map_defs(&mut skel, &mut object, &obj_name, false, false)?;
    gen_skel_map_defs(&mut skel, &mut object, &obj_name, false, true)?;
    gen_skel_prog_defs(&mut skel, &mut object, &obj_name, false, false)?;
    gen_skel_prog_defs(&mut skel, &mut object, &obj_name, false, true)?;
    gen_skel_link_defs(&mut skel, &mut object, &obj_name)?;

    write!(
        skel,
        r#"
        pub struct {name}Skel<'a> {{
            pub obj: libbpf_rs::Object,
            skel_config: libbpf_rs::skeleton::ObjectSkeletonConfig<'a>,
        "#,
        name = &obj_name,
    )?;
    gen_skel_link_getter(&mut skel, &mut object, &obj_name)?;
    write!(
        skel,
        r#"
        }}

        unsafe impl<'a> Send for {name}Skel<'a> {{}}

        impl<'a> {name}Skel<'a> {{
        "#,
        name = &obj_name,
    )?;
    gen_skel_prog_getter(&mut skel, &mut object, &obj_name, false, false)?;
    gen_skel_prog_getter(&mut skel, &mut object, &obj_name, false, true)?;
    gen_skel_map_getter(&mut skel, &mut object, &obj_name, false, false)?;
    gen_skel_map_getter(&mut skel, &mut object, &obj_name, false, true)?;
    gen_skel_datasec_getters(&mut skel, &mut object, raw_obj_name, true)?;
    gen_skel_attach(&mut skel, &mut object, &obj_name)?;
    writeln!(skel, "}}")?;

    // Coerce to &[u8] just to be safe, as we'll be using debug formatting
    let bytes: &[u8] = &mmap;
    write!(
        skel,
        r#"
        const DATA: &[u8] = &{:?};
        "#,
        bytes
    )?;

    writeln!(skel, "}}")?;

    Ok(skel)
}

/// Generate a single skeleton
fn gen_skel(
    debug: bool,
    name: &str,
    obj: &Path,
    out: OutputDest,
    rustfmt_path: Option<&PathBuf>,
) -> Result<()> {
    if name.is_empty() {
        bail!("Object file has no name");
    }

    let skel = rustfmt(&gen_skel_contents(debug, name, obj)?, rustfmt_path)?;

    match out {
        OutputDest::Stdout => print!("{}", skel),
        OutputDest::Directory(dir) => {
            let path = dir.join(format!("{}.skel.rs", name));
            let mut file = File::create(path)?;
            file.write_all(skel.as_bytes())?;
        }
        OutputDest::File(file) => {
            let mut file = File::create(file)?;
            file.write_all(skel.as_bytes())?;
        }
    };

    Ok(())
}

/// Generate mod.rs in src/bpf directory of each project.
///
/// Each `UnprocessedObj` in `objs` must belong to same project.
pub fn gen_mods(objs: &[UnprocessedObj], rustfmt_path: Option<&PathBuf>) -> Result<()> {
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
    file.write_all(rustfmt(&contents, rustfmt_path)?.as_bytes())?;

    Ok(())
}

pub fn gen_single(
    debug: bool,
    obj_file: &Path,
    output: OutputDest,
    rustfmt_path: Option<&PathBuf>,
) -> Result<()> {
    let filename = match obj_file.file_name() {
        Some(n) => n,
        None => bail!(
            "Could not determine file name for object file: {}",
            obj_file.to_string_lossy()
        ),
    };

    let name = match filename.to_str() {
        Some(n) => {
            if !n.ends_with(".o") {
                bail!("Object file does not have `.o` suffix: {}", n);
            }

            n.split('.').next().unwrap()
        }
        None => bail!(
            "Object file name is not valid unicode: {}",
            filename.to_string_lossy()
        ),
    };

    if let Err(e) = gen_skel(debug, name, obj_file, output, rustfmt_path) {
        bail!(
            "Failed to generate skeleton for {}: {}",
            obj_file.to_string_lossy(),
            e
        );
    }

    Ok(())
}

fn gen_project(
    debug: bool,
    manifest_path: Option<&PathBuf>,
    rustfmt_path: Option<&PathBuf>,
) -> Result<()> {
    let (_target_dir, to_gen) = metadata::get(debug, manifest_path)?;
    if debug && !to_gen.is_empty() {
        println!("Found bpf objs to gen skel:");
        for obj in &to_gen {
            println!("\t{:?}", obj);
        }
    } else if to_gen.is_empty() {
        bail!("Did not find any bpf objects to generate skeleton");
    }

    // Map to store package_name -> [UnprocessedObj]
    let mut package_objs: BTreeMap<String, Vec<UnprocessedObj>> = BTreeMap::new();

    for obj in to_gen {
        let mut obj_file_path = obj.out.clone();
        obj_file_path.push(format!("{}.bpf.o", obj.name));

        let mut skel_path = obj.path.clone();
        skel_path.pop();

        match gen_skel(
            debug,
            &obj.name,
            obj_file_path.as_path(),
            OutputDest::Directory(skel_path.as_path()),
            rustfmt_path,
        ) {
            Ok(_) => (),
            Err(e) => bail!(
                "Failed to generate skeleton for {}: {}",
                obj.path.as_path().display(),
                e
            ),
        }

        match package_objs.get_mut(&obj.package) {
            Some(v) => v.push(obj.clone()),
            None => {
                package_objs.insert(obj.package.clone(), vec![obj.clone()]);
            }
        };
    }

    for (package, objs) in package_objs {
        if let Err(e) = gen_mods(&objs, rustfmt_path) {
            bail!("Failed to generate mod.rs for package={}: {}", package, e);
        }
    }

    Ok(())
}

pub fn gen(
    debug: bool,
    manifest_path: Option<&PathBuf>,
    rustfmt_path: Option<&PathBuf>,
    object: Option<&PathBuf>,
) -> Result<()> {
    if manifest_path.is_some() && object.is_some() {
        bail!("--manifest-path and --object cannot be used together");
    }

    if let Some(obj_file) = object {
        gen_single(debug, obj_file, OutputDest::Stdout, rustfmt_path)
    } else {
        gen_project(debug, manifest_path, rustfmt_path)
    }
}
