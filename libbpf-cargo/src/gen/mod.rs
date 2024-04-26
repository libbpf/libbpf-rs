pub mod btf;

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::ffi::c_void;
use std::ffi::CStr;
use std::ffi::CString;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fmt::Write as fmt_write;
use std::fs::File;
use std::io::stdout;
use std::io::ErrorKind;
use std::io::Write;
use std::mem::size_of;
use std::ops::Deref;
use std::os::raw::c_ulong;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::ptr;

use anyhow::bail;
use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;

use libbpf_rs::btf::types;
use libbpf_rs::libbpf_sys;
use libbpf_rs::Btf;

use memmap2::Mmap;

use crate::metadata;
use crate::metadata::UnprocessedObj;

use self::btf::GenBtf;

/// Escape certain characters in a "raw" name of a section, for example.
fn escape_raw_name(name: &str) -> String {
    name.replace('.', "_")
}

#[derive(Debug, PartialEq)]
pub(crate) enum InternalMapType<'name> {
    Data,
    CustomData(&'name str),
    Rodata,
    CustomRodata(&'name str),
    Bss,
    CustomBss(&'name str),
    Kconfig,
    StructOps,
}

impl Display for InternalMapType<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Data => write!(f, "data"),
            Self::CustomData(name) => write!(f, "data_{}", escape_raw_name(name)),
            Self::Rodata => write!(f, "rodata"),
            Self::CustomRodata(name) => write!(f, "rodata_{}", escape_raw_name(name)),
            Self::Bss => write!(f, "bss"),
            Self::CustomBss(name) => write!(f, "bss_{}", escape_raw_name(name)),
            Self::Kconfig => write!(f, "kconfig"),
            Self::StructOps => write!(f, "struct_ops"),
        }
    }
}

#[repr(transparent)]
pub(crate) struct BpfObj(ptr::NonNull<libbpf_sys::bpf_object>);

impl BpfObj {
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut libbpf_sys::bpf_object {
        self.0.as_ptr()
    }
}

impl Deref for BpfObj {
    type Target = libbpf_sys::bpf_object;

    fn deref(&self) -> &Self::Target {
        // SAFETY: Our `bpf_object` pointer is always valid.
        unsafe { self.0.as_ref() }
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

/// Try running `rustfmt` over `s` and return result.
///
/// If no `rustfmt` binary could be found the content is left untouched, as
/// it's only meant as a cosmetic brush up, without change of semantics.
fn try_rustfmt<'code>(s: &'code str, rustfmt_path: Option<&PathBuf>) -> Result<Cow<'code, [u8]>> {
    let result = if let Some(r) = rustfmt_path {
        Command::new(r)
    } else {
        Command::new("rustfmt")
    }
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .spawn();

    match result {
        Ok(mut cmd) => {
            // Send input in via stdin
            cmd.stdin.take().unwrap().write_all(s.as_bytes())?;

            // Extract output
            let output = cmd
                .wait_with_output()
                .context("Failed to execute rustfmt")?;
            ensure!(
                output.status.success(),
                "Failed to rustfmt: {}",
                output.status
            );

            Ok(output.stdout.into())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            // No `rustfmt` is present. Just skip formatting altogether.
            Ok(Cow::Borrowed(s.as_bytes()))
        }
        Err(err) => panic!("failed to spawn rustfmt: {err}"),
    }
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
    ensure!(!name_ptr.is_null(), "Map name unknown");

    Ok(unsafe { CStr::from_ptr(name_ptr) }.to_str()?.to_string())
}

pub(crate) fn canonicalize_internal_map_name(s: &str) -> Option<InternalMapType<'_>> {
    if s.ends_with(".data") {
        Some(InternalMapType::Data)
    } else if s.ends_with(".rodata") {
        Some(InternalMapType::Rodata)
    } else if s.ends_with(".bss") {
        Some(InternalMapType::Bss)
    } else if s.ends_with(".kconfig") {
        Some(InternalMapType::Kconfig)
    } else if s.ends_with(".struct_ops") {
        Some(InternalMapType::StructOps)
    } else if s.ends_with(".struct_ops.link") {
        // The `*.link` extension really only sets an additional flag in lower
        // layers. For our intents and purposes both can be treated similarly.
        Some(InternalMapType::StructOps)
    // Custom data sections don't prepend bpf_object name, so we can match from
    // start of name.
    // See https://github.com/libbpf/libbpf/blob/20ea95b4505c477af3b6ff6ce9d19cee868ddc5d/src/libbpf.c#L1789-L1794
    } else if s.starts_with(".data.") {
        let name = s.get(".data.".len()..).unwrap();
        Some(InternalMapType::CustomData(name))
    } else if s.starts_with(".rodata.") {
        let name = s.get(".rodata.".len()..).unwrap();
        Some(InternalMapType::CustomRodata(name))
    } else if s.starts_with(".bss.") {
        let name = s.get(".bss.".len()..).unwrap();
        Some(InternalMapType::CustomBss(name))
    } else {
        eprintln!("Warning: unrecognized map: {s}");
        None
    }
}

/// Same as `get_raw_map_name` except the name is canonicalized
fn get_map_name(map: *const libbpf_sys::bpf_map) -> Result<Option<String>> {
    let name = get_raw_map_name(map)?;

    if unsafe { !libbpf_sys::bpf_map__is_internal(map) } {
        Ok(Some(escape_raw_name(&name)))
    } else {
        Ok(canonicalize_internal_map_name(&name).map(|map| map.to_string()))
    }
}

fn get_prog_name(prog: *const libbpf_sys::bpf_program) -> Result<String> {
    let name_ptr = unsafe { libbpf_sys::bpf_program__name(prog) };
    ensure!(!name_ptr.is_null(), "Prog name unknown");

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
        fn build_skel_config() -> libbpf_rs::Result<libbpf_rs::__internal_skel::ObjectSkeletonConfig<'static>>
        {{
            let mut builder = libbpf_rs::__internal_skel::ObjectSkeletonConfigBuilder::new(DATA);
            builder
                .name("{name}")
        "#,
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
        )?;
    }

    for prog in ProgIter::new(object.as_mut_ptr()) {
        let name = get_prog_name(prog)?;

        write!(
            skel,
            r#"
            .prog("{name}")
            "#,
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
) -> Result<()> {
    let mut gen = |mutable| -> Result<()> {
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
                format!("Open{obj_name}Maps{struct_suffix}"),
                "libbpf_rs::OpenObject",
                "libbpf_rs::OpenMap",
            )
        } else {
            (
                format!("{obj_name}Maps{struct_suffix}"),
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

            impl {struct_name}<'_> {{
            "#,
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
    };

    let () = gen(true)?;
    let () = gen(false)?;
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
            format!("Open{obj_name}Progs{struct_suffix}"),
            "libbpf_rs::OpenObject",
            "libbpf_rs::OpenProgram",
        )
    } else {
        (
            format!("{obj_name}Progs{struct_suffix}"),
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

        impl {struct_name}<'_> {{
        "#,
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

fn gen_skel_datasec_types(skel: &mut String, object: &BpfObj) -> Result<()> {
    let btf = if let Some(btf) = Btf::from_bpf_object(object)? {
        btf
    } else {
        return Ok(());
    };
    let btf = GenBtf::from(btf);

    let mut processed = HashSet::new();
    for ty in btf.type_by_kind::<types::DataSec<'_>>() {
        let name = match ty.name() {
            Some(s) => s.to_str()?,
            None => "",
        };

        if matches!(
            canonicalize_internal_map_name(name),
            None | Some(InternalMapType::StructOps)
        ) {
            continue;
        };

        let sec_def = btf.type_definition(*ty, &mut processed)?;
        write!(skel, "{sec_def}")?;
    }
    Ok(())
}

fn gen_skel_struct_ops_types(
    skel: &mut String,
    object: &BpfObj, /*, programs: &mut HashMap*/
) -> Result<()> {
    if let Some(btf) = Btf::from_bpf_object(object)? {
        let btf = GenBtf::from(btf);

        let mut processed = HashSet::new();
        let def = btf.struct_ops_type_definition(&mut processed)?;
        write!(skel, "{def}")?;
    } else {
        write!(
            skel,
            r#"
#[derive(Debug, Clone)]
#[repr(C)]
pub struct struct_ops {{}}
"#
        )?;
    }
    Ok(())
}

fn gen_skel_map_getters(
    skel: &mut String,
    object: &mut BpfObj,
    obj_name: &str,
    open: bool,
) -> Result<()> {
    let mut gen = |mutable| -> Result<()> {
        if MapIter::new(object.as_mut_ptr()).next().is_none() {
            return Ok(());
        }

        let (struct_suffix, mut_prefix, map_fn) = if mutable {
            ("Mut", "mut ", "maps_mut")
        } else {
            ("", "", "maps")
        };

        let return_ty = if open {
            format!("Open{obj_name}Maps{struct_suffix}")
        } else {
            format!("{obj_name}Maps{struct_suffix}")
        };

        write!(
            skel,
            r#"
            pub fn {map_fn}(&{mut_prefix}self) -> {return_ty}<'_> {{
                {return_ty} {{
                    inner: &{mut_prefix}self.obj,
                }}
            }}
            "#,
        )?;

        Ok(())
    };

    let () = gen(true)?;
    let () = gen(false)?;
    Ok(())
}

fn gen_skel_struct_ops_getters(
    skel: &mut String,
    object: &mut BpfObj,
    obj_name: &str,
) -> Result<()> {
    if MapIter::new(object.as_mut_ptr()).next().is_none() {
        return Ok(());
    }

    write!(
        skel,
        r#"
        pub fn struct_ops_raw(&self) -> *const {obj_name}_types::struct_ops {{
            &self.struct_ops
        }}

        pub fn struct_ops(&self) -> &{obj_name}_types::struct_ops {{
            &self.struct_ops
        }}
        "#,
    )?;

    Ok(())
}

fn gen_skel_prog_getters(
    skel: &mut String,
    object: &mut BpfObj,
    obj_name: &str,
    open: bool,
) -> Result<()> {
    let mut gen = |mutable| -> Result<()> {
        if ProgIter::new(object.as_mut_ptr()).next().is_none() {
            return Ok(());
        }

        let (struct_suffix, mut_prefix, prog_fn) = if mutable {
            ("Mut", "mut ", "progs_mut")
        } else {
            ("", "", "progs")
        };

        let return_ty = if open {
            format!("Open{obj_name}Progs{struct_suffix}")
        } else {
            format!("{obj_name}Progs{struct_suffix}")
        };

        write!(
            skel,
            r#"
            pub fn {prog_fn}(&{mut_prefix}self) -> {return_ty}<'_> {{
                {return_ty} {{
                    inner: &{mut_prefix}self.obj,
                }}
            }}
            "#,
        )?;

        Ok(())
    };

    let () = gen(true)?;
    let () = gen(false)?;
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
        let struct_name = format!("{obj_name}_types::{name}");
        let immutable = loaded && map_is_readonly(map);
        let mutabilities = if immutable {
            [false].as_ref()
        } else {
            [false, true].as_ref()
        };

        for mutable in mutabilities {
            let (ref_suffix, ptr_suffix, fn_suffix) = if *mutable {
                ("mut", "mut", "_mut")
            } else {
                ("", "const", "")
            };

            write!(
                skel,
                r#"
                pub fn {name}{fn_suffix}_raw(&{ref_suffix} self) -> *{ptr_suffix} {struct_name} {{
                    self.skel_config.map_mmap_ptr{fn_suffix}({idx}).unwrap().cast::<{struct_name}>()
                }}

                pub fn {name}{fn_suffix}(&{ref_suffix} self) -> &{ref_suffix} {struct_name} {{
                    unsafe {{&{ref_suffix}*self.{name}{fn_suffix}_raw()}}
                }}
                "#
            )?;
        }
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
        pub struct {obj_name}Links {{
        "#,
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
        r#"pub links: {obj_name}Links,
        "#
    )?;

    Ok(())
}

fn open_bpf_object(name: &str, data: &[u8]) -> Result<BpfObj> {
    let cname = CString::new(name)?;
    let obj_opts = libbpf_sys::bpf_object_open_opts {
        sz: size_of::<libbpf_sys::bpf_object_open_opts>() as libbpf_sys::size_t,
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
    ensure!(!object.is_null(), "Failed to bpf_object__open_mem()");

    Ok(BpfObj(ptr::NonNull::new(object).unwrap()))
}

fn gen_skel_attach(skel: &mut String, object: &mut BpfObj, obj_name: &str) -> Result<()> {
    if ProgIter::new(object.as_mut_ptr()).next().is_none() {
        return Ok(());
    }

    write!(
        skel,
        r#"
        fn attach(&mut self) -> libbpf_rs::Result<()> {{
            let ret = unsafe {{ libbpf_sys::bpf_object__attach_skeleton(self.skel_config.get()) }};
            if ret != 0 {{
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }}

            self.links = {obj_name}Links {{
        "#,
    )?;

    for (idx, prog) in ProgIter::new(object.as_mut_ptr()).enumerate() {
        let prog_name = get_prog_name(prog)?;

        write!(
            skel,
            r#"{prog_name}: core::ptr::NonNull::new(self.skel_config.prog_link_ptr({idx})?)
                        .map(|ptr| unsafe {{ libbpf_rs::Link::from_ptr(ptr) }}),
            "#
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

fn gen_skel_struct_ops_init(object: &mut BpfObj) -> Result<String> {
    let mut def = String::new();

    for map in MapIter::new(object.as_mut_ptr()) {
        let type_ = unsafe { libbpf_sys::bpf_map__type(map) };
        if type_ != libbpf_sys::BPF_MAP_TYPE_STRUCT_OPS {
            continue;
        }

        let raw_name = get_raw_map_name(map)?;

        write!(
            def,
            r#"
            skel.struct_ops.{raw_name} = skel.maps_mut().{raw_name}().initial_value_mut().unwrap().as_mut_ptr().cast();
            "#,
        )?;
    }
    Ok(def)
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
           #[allow(clippy::absolute_paths)]
           #[allow(clippy::transmute_ptr_to_ref)]
           #[allow(clippy::upper_case_acronyms)]
           #[warn(single_use_lifetimes)]
           mod imp {{
           #[allow(unused_imports)]
           use super::*;
           use libbpf_rs::libbpf_sys;
           use libbpf_rs::skel::OpenSkel;
           use libbpf_rs::skel::Skel;
           use libbpf_rs::skel::SkelBuilder;
        "#
    )?;

    // The name we'll always hand to libbpf
    //
    // Note it's important this remains consistent b/c libbpf infers map/prog names from this name
    let libbpf_obj_name = format!("{raw_obj_name}_bpf");
    // We'll use `obj_name` as the rust-ified object name
    let obj_name = capitalize_first_letter(raw_obj_name);

    // Open bpf_object so we can iterate over maps and progs
    let file = File::open(obj_file_path)
        .with_context(|| format!("failed to open BPF object `{}`", obj_file_path.display()))?;
    let mmap = unsafe { Mmap::map(&file)? };
    let mut object = open_bpf_object(&libbpf_obj_name, &mmap)?;

    gen_skel_c_skel_constructor(&mut skel, &mut object, &libbpf_obj_name)?;

    #[allow(clippy::uninlined_format_args)]
    write!(
        skel,
        r#"
        #[derive(Default)]
        pub struct {name}SkelBuilder {{
            pub obj_builder: libbpf_rs::ObjectBuilder,
        }}

        impl<'a> SkelBuilder<'a> for {name}SkelBuilder {{
            type Output = Open{name}Skel<'a>;
            fn open(self) -> libbpf_rs::Result<Open{name}Skel<'a>> {{
                let opts = *self.obj_builder.opts();
                self.open_opts(opts)
            }}

            fn open_opts(self, open_opts: libbpf_sys::bpf_object_open_opts) -> libbpf_rs::Result<Open{name}Skel<'a>> {{
                let mut skel_config = build_skel_config()?;

                let ret = unsafe {{ libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) }};
                if ret != 0 {{
                    return Err(libbpf_rs::Error::from_raw_os_error(-ret));
                }}

                let obj = unsafe {{ libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? }};

                #[allow(unused_mut)]
                let mut skel = Open{name}Skel {{
                    obj,
                    // SAFETY: Our `struct_ops` type contains only pointers,
                    //         which are allowed to be NULL.
                    // TODO: Generate and use a `Default` representation
                    //       instead, to cut down on unsafe code.
                    struct_ops: unsafe {{ std::mem::zeroed() }},
                    skel_config
                }};
                {struct_ops_init}
                Ok(skel)
            }}

            fn object_builder(&self) -> &libbpf_rs::ObjectBuilder {{
                &self.obj_builder
            }}
            fn object_builder_mut(&mut self) -> &mut libbpf_rs::ObjectBuilder {{
                &mut self.obj_builder
            }}
        }}
        "#,
        name = obj_name,
        struct_ops_init = gen_skel_struct_ops_init(&mut object)?,
    )?;

    gen_skel_map_defs(&mut skel, &mut object, &obj_name, true)?;
    gen_skel_prog_defs(&mut skel, &mut object, &obj_name, true, false)?;
    gen_skel_prog_defs(&mut skel, &mut object, &obj_name, true, true)?;
    write!(
        skel,
        r#"
            pub mod {raw_obj_name}_types {{
                #[allow(unused_imports)]
                use super::*;
            "#
    )?;

    gen_skel_datasec_types(&mut skel, &object)?;
    gen_skel_struct_ops_types(&mut skel, &object)?;
    writeln!(skel, "}}")?;

    write!(
        skel,
        r#"
        pub struct Open{name}Skel<'a> {{
            pub obj: libbpf_rs::OpenObject,
            pub struct_ops: {raw_obj_name}_types::struct_ops,
            skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'a>,
        }}

        impl<'a> OpenSkel for Open{name}Skel<'a> {{
            type Output = {name}Skel<'a>;
            fn load(mut self) -> libbpf_rs::Result<{name}Skel<'a>> {{
                let ret = unsafe {{ libbpf_sys::bpf_object__load_skeleton(self.skel_config.get()) }};
                if ret != 0 {{
                    return Err(libbpf_rs::Error::from_raw_os_error(-ret));
                }}

                let obj = unsafe {{ libbpf_rs::Object::from_ptr(self.obj.take_ptr())? }};

                Ok({name}Skel {{
                    obj,
                    struct_ops: self.struct_ops,
                    skel_config: self.skel_config,
                    {links}
                }})
            }}

            fn open_object(&self) -> &libbpf_rs::OpenObject {{
                &self.obj
            }}

            fn open_object_mut(&mut self) -> &mut libbpf_rs::OpenObject {{
                &mut self.obj
            }}
        "#,
        name = &obj_name,
        links = if ProgIter::new(object.as_mut_ptr()).next().is_some() {
            format!(r#"links: {obj_name}Links::default()"#)
        } else {
            "".to_string()
        }
    )?;
    writeln!(skel, "}}")?;
    writeln!(skel, "impl Open{name}Skel<'_> {{", name = &obj_name)?;

    gen_skel_prog_getters(&mut skel, &mut object, &obj_name, true)?;
    gen_skel_map_getters(&mut skel, &mut object, &obj_name, true)?;
    gen_skel_datasec_getters(&mut skel, &mut object, raw_obj_name, false)?;
    writeln!(skel, "}}")?;

    gen_skel_map_defs(&mut skel, &mut object, &obj_name, false)?;
    gen_skel_prog_defs(&mut skel, &mut object, &obj_name, false, false)?;
    gen_skel_prog_defs(&mut skel, &mut object, &obj_name, false, true)?;
    gen_skel_link_defs(&mut skel, &mut object, &obj_name)?;

    write!(
        skel,
        r#"
        pub struct {name}Skel<'a> {{
            pub obj: libbpf_rs::Object,
            struct_ops: {raw_obj_name}_types::struct_ops,
            skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'a>,
        "#,
        name = &obj_name,
    )?;
    gen_skel_link_getter(&mut skel, &mut object, &obj_name)?;
    write!(
        skel,
        r#"
        }}

        unsafe impl Send for {name}Skel<'_> {{}}
        unsafe impl Sync for {name}Skel<'_> {{}}

        impl Skel for {name}Skel<'_> {{
            fn object(&self) -> &libbpf_rs::Object {{
                &self.obj
            }}

            fn object_mut(&mut self) -> &mut libbpf_rs::Object {{
                &mut self.obj
            }}
        "#,
        name = &obj_name,
    )?;
    gen_skel_attach(&mut skel, &mut object, &obj_name)?;
    writeln!(skel, "}}")?;

    write!(skel, "impl {name}Skel<'_> {{", name = &obj_name)?;
    gen_skel_prog_getters(&mut skel, &mut object, &obj_name, false)?;
    gen_skel_map_getters(&mut skel, &mut object, &obj_name, false)?;
    gen_skel_struct_ops_getters(&mut skel, &mut object, raw_obj_name)?;
    gen_skel_datasec_getters(&mut skel, &mut object, raw_obj_name, true)?;
    writeln!(skel, "}}")?;

    // Coerce to &[u8] just to be safe, as we'll be using debug formatting
    let bytes: &[u8] = &mmap;
    write!(
        skel,
        r#"
        const DATA: &[u8] = &{bytes:?};
        "#
    )?;

    writeln!(skel, "}}")?;

    Ok(skel)
}

/// Generate a single skeleton
fn gen_skel(
    debug: bool,
    name: &str,
    obj: &Path,
    out: OutputDest<'_>,
    rustfmt_path: Option<&PathBuf>,
) -> Result<()> {
    ensure!(!name.is_empty(), "Object file has no name");

    let skel = gen_skel_contents(debug, name, obj)?;
    let skel = try_rustfmt(&skel, rustfmt_path)?;

    match out {
        OutputDest::Stdout => stdout().write_all(&skel)?,
        OutputDest::Directory(dir) => {
            let path = dir.join(format!("{name}.skel.rs"));
            let mut file = File::create(path)?;
            file.write_all(&skel)?;
        }
        OutputDest::File(file) => {
            let mut file = File::create(file)?;
            file.write_all(&skel)?;
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
    file.write_all(&try_rustfmt(&contents, rustfmt_path)?)?;

    Ok(())
}

pub fn gen_single(
    debug: bool,
    obj_file: &Path,
    output: OutputDest<'_>,
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
            ensure!(
                n.ends_with(".o"),
                "Object file does not have `.o` suffix: {n}"
            );

            n.split('.').next().unwrap()
        }
        None => bail!(
            "Object file name is not valid unicode: {}",
            filename.to_string_lossy()
        ),
    };

    let () = gen_skel(debug, name, obj_file, output, rustfmt_path).with_context(|| {
        format!(
            "Failed to generate skeleton for {}",
            obj_file.to_string_lossy(),
        )
    })?;

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
            println!("\t{obj:?}");
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

        let () = gen_skel(
            debug,
            &obj.name,
            obj_file_path.as_path(),
            OutputDest::Directory(skel_path.as_path()),
            rustfmt_path,
        )
        .with_context(|| {
            format!(
                "Failed to generate project skeleton for {}",
                obj.path.as_path().display()
            )
        })?;

        match package_objs.get_mut(&obj.package) {
            Some(v) => v.push(obj.clone()),
            None => {
                package_objs.insert(obj.package.clone(), vec![obj.clone()]);
            }
        };
    }

    for (package, objs) in package_objs {
        let () = gen_mods(&objs, rustfmt_path)
            .with_context(|| format!("Failed to generate mod.rs for package={package}"))?;
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
