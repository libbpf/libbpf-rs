pub mod btf;

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::ffi::c_void;
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

use libbpf_rs::btf::BtfType;
use libbpf_rs::btf::TypeId;
use libbpf_rs::libbpf_sys;
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::Btf;
use libbpf_rs::Map;
use libbpf_rs::MapCore as _;
use libbpf_rs::MapIter;
use libbpf_rs::MapType;
use libbpf_rs::Object;
use libbpf_rs::Program;

use memmap2::Mmap;

use crate::metadata;
use crate::metadata::UnprocessedObj;

use self::btf::GenBtf;
use self::btf::GenStructOps;


/// Name of the `.kconfig` map.
///
/// It requires special treatment because `libbpf` doesn't set the
/// corresponding mmap pointer during "open", only as part of "load".
const MAP_NAME_KCONFIG: &str = "kconfig";


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


/// Meta-data about a BPF map.
enum MapMeta {
    NonDatasec,
    Datasec {
        mmap_idx: usize,
        read_only: bool,
        not_openable: bool,
    },
}

impl MapMeta {
    fn new(name: &str, idx: usize, map: &Map<'_>) -> Self {
        if map_is_datasec(map) {
            Self::Datasec {
                mmap_idx: idx,
                read_only: map_is_readonly(map),
                not_openable: name == MAP_NAME_KCONFIG,
            }
        } else {
            Self::NonDatasec
        }
    }
}


/// Data about a single BPF map.
struct MapData {
    raw_name: String,
    name: String,
    meta: MapMeta,
}

impl MapData {
    fn new(idx: usize, map: &Map<'_>) -> Result<Option<Self>> {
        let raw_name = map.name();
        let raw_name = raw_name
            .to_str()
            .with_context(|| format!("map has invalid name: {raw_name:?}"))?
            .to_string();

        // TODO: Should work with `raw_name` here instead of retrieving it
        //       again internally.
        let name = if let Some(name) = get_map_name(map)? {
            name.to_string()
        } else {
            return Ok(None)
        };

        let slf = Self {
            raw_name,
            meta: MapMeta::new(&name, idx, map),
            name,
        };
        Ok(Some(slf))
    }
}


/// Data pertaining BPF maps used as part of code generation.
struct MapsData {
    /// Vector of data about individual BPF maps, in the same order as
    /// they appear in the underlying object file.
    maps: Vec<MapData>,
}

impl MapsData {
    fn new(obj: &Object) -> Result<Self> {
        let maps = maps(obj)
            .enumerate()
            .filter_map(|(idx, map)| MapData::new(idx, &map).transpose())
            .collect::<Result<Vec<_>>>()?;
        let slf = Self { maps };
        Ok(slf)
    }

    fn iter(&self) -> impl Iterator<Item = &MapData> {
        self.maps.iter()
    }
}


/// Data pertaining BPF programs used as part of code generation.
struct ProgsData {
    /// Vector of names of individual BPF programs, in the same order as they
    /// appear in the underlying object file.
    progs: Vec<String>,
}

impl ProgsData {
    fn new(obj: &Object) -> Result<Self> {
        let progs = obj
            .progs()
            .map(|prog| get_prog_name(&prog))
            .collect::<Result<Vec<_>>>()?;
        let slf = Self { progs };
        Ok(slf)
    }

    fn iter(&self) -> impl Iterator<Item = &String> {
        self.progs.iter()
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

fn get_raw_map_name(map: &Map<'_>) -> Result<String> {
    let name = map
        .name()
        .to_str()
        .context("map has invalid name")?
        .to_string();
    Ok(name)
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
fn get_map_name(map: &Map<'_>) -> Result<Option<String>> {
    let name = get_raw_map_name(map)?;

    if unsafe { !libbpf_sys::bpf_map__is_internal(map.as_libbpf_object().as_ptr()) } {
        Ok(Some(escape_raw_name(&name)))
    } else {
        Ok(canonicalize_internal_map_name(&name).map(|map| map.to_string()))
    }
}

fn get_prog_name(prog: &Program<'_>) -> Result<String> {
    let name = prog
        .name()
        .to_str()
        .context("program has invalid name")?
        .to_string();
    Ok(name)
}

fn map_is_mmapable(map: &Map<'_>) -> bool {
    let map_ptr = map.as_libbpf_object().as_ptr();
    (unsafe { libbpf_sys::bpf_map__map_flags(map_ptr) } & libbpf_sys::BPF_F_MMAPABLE) > 0
}

fn map_is_datasec(map: &Map<'_>) -> bool {
    let internal = unsafe { libbpf_sys::bpf_map__is_internal(map.as_libbpf_object().as_ptr()) };
    let mmapable = map_is_mmapable(map);

    internal && mmapable
}

fn map_is_readonly(map: &Map<'_>) -> bool {
    assert!(map_is_mmapable(map));

    let map_ptr = map.as_libbpf_object().as_ptr();
    // BPF_F_RDONLY_PROG means readonly from prog side
    (unsafe { libbpf_sys::bpf_map__map_flags(map_ptr) } & libbpf_sys::BPF_F_RDONLY_PROG) > 0
}

fn maps(object: &Object) -> impl Iterator<Item = Map<'_>> {
    // SAFETY: The pointer returned by `as_libbpf_object` is always valid.
    let obj = unsafe { object.as_libbpf_object().as_ref() };
    MapIter::new(obj)
        // SAFETY: Map iteration always yields valid objects.
        .filter(|ptr| unsafe { libbpf_sys::bpf_map__autocreate(ptr.as_ptr()) })
        // SAFETY: We never use the `AsFd` impl of the map.
        .map(|ptr| unsafe { Map::from_map_without_fd(ptr) })
}

fn gen_skel_c_skel_constructor(skel: &mut String, object: &Object, name: &str) -> Result<()> {
    write!(
        skel,
        "\
        fn build_skel_config() -> libbpf_rs::Result<libbpf_rs::__internal_skel::ObjectSkeletonConfig<'static>>
        {{
            let mut builder = libbpf_rs::__internal_skel::ObjectSkeletonConfigBuilder::new(DATA);
            builder
                .name(\"{name}\")
        ",
    )?;

    for map in maps(object) {
        let raw_name = get_raw_map_name(&map)?;
        let mmaped = if map_is_mmapable(&map) {
            "true"
        } else {
            "false"
        };

        writeln!(skel, ".map(\"{raw_name}\", {mmaped})")?;
    }

    for prog in object.progs() {
        let name = get_prog_name(&prog)?;
        writeln!(skel, ".prog(\"{name}\")")?;
    }

    writeln!(skel, ";")?;

    write!(
        skel,
        "\
            builder.build()
        }}
        "
    )?;

    Ok(())
}

fn gen_skel_map_defs(
    skel: &mut String,
    maps: &MapsData,
    raw_obj_name: &str,
    open: bool,
) -> Result<()> {
    let prefix = if open { "Open" } else { "" };

    let obj_name = capitalize_first_letter(raw_obj_name);
    write!(
        skel,
        "\
                pub struct {prefix}{obj_name}Maps<'obj> {{
        ",
    )?;

    for map in maps.iter() {
        write!(
            skel,
            "\
                    pub {name}: libbpf_rs::{prefix}MapMut<'obj>,
            ",
            name = map.name
        )?;

        if let MapMeta::Datasec {
            read_only,
            not_openable,
            ..
        } = map.meta
        {
            if !(open && not_openable) {
                // After "open" all maps are writable. That's the point,
                // they can be modified.
                let ref_mut = if open || !read_only { " mut" } else { "" };
                write!(
                    skel,
                    "\
                        pub {name}_data: &'obj{ref_mut} types::{name},
                    ",
                    name = map.name,
                )?;
            }
        }
    }

    write!(
        skel,
        "\
                    _phantom: std::marker::PhantomData<&'obj ()>,
                }}

                impl<'obj> {prefix}{obj_name}Maps<'obj> {{
                    #[allow(unused_variables)]
                    unsafe fn new(
                        config: &libbpf_rs::__internal_skel::ObjectSkeletonConfig<'_>,
                        object: &mut libbpf_rs::{prefix}Object,
                    ) -> libbpf_rs::Result<Self> {{
        ",
    )?;

    for map in maps.iter() {
        writeln!(skel, "let mut {name} = None;", name = map.name)?;
    }

    write!(
        skel,
        "\
                        let object = unsafe {{
                            std::mem::transmute::<&mut libbpf_rs::{prefix}Object, &'obj mut libbpf_rs::{prefix}Object>(object)
                        }};
                        #[allow(clippy::never_loop)]
                        for map in object.maps_mut() {{
                            let name = map
                                .name()
                                .to_str()
                                .ok_or_else(|| {{
                                    libbpf_rs::Error::from(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        \"map has invalid name\",
                                    ))
                                }})?;
                            #[allow(clippy::match_single_binding)]
                            match name {{
        ",
    )?;

    for map in maps.iter() {
        write!(
            skel,
            "\
                                \"{raw_name}\" => {name} = Some(map),
            ",
            raw_name = map.raw_name,
            name = map.name
        )?;
    }

    write!(
        skel,
        "\
                                _ => panic!(\"encountered unexpected map: `{{name}}`\"),
                            }}
                        }}

                        let slf = Self {{
        ",
    )?;

    for map in maps.iter() {
        write!(
            skel,
            "\
                            {name}: {name}.expect(\"map `{name}` not present\"),
            ",
            name = map.name
        )?;

        if let MapMeta::Datasec {
            mmap_idx,
            read_only,
            not_openable,
        } = map.meta
        {
            if !(open && not_openable) {
                let ref_conv = if open || !read_only { "mut" } else { "ref" };
                write!(
                    skel,
                    "\
                                {name}_data: unsafe {{
                                    config
                                        .map_mmap_ptr({mmap_idx})
                                        .expect(\"BPF map `{name}` does not have mmap pointer\")
                                        .cast::<types::{name}>()
                                        .as_{ref_conv}()
                                        .expect(\"BPF map `{name}` mmap pointer is NULL\")
                                }},
                    ",
                    name = map.name,
                )?;
            }
        }
    }

    write!(
        skel,
        "\
                            _phantom: std::marker::PhantomData,
                        }};
                        Ok(slf)
                    }}
                }}
        ",
    )?;
    Ok(())
}

fn gen_skel_open_prog_defs(skel: &mut String, progs: &ProgsData, raw_obj_name: &str) -> Result<()> {
    let obj_name = capitalize_first_letter(raw_obj_name);
    write!(
        skel,
        "\
                pub struct Open{obj_name}Progs<'obj> {{
        ",
    )?;

    for name in progs.iter() {
        write!(
            skel,
            "\
                    pub {name}: libbpf_rs::OpenProgramMut<'obj>,
            ",
        )?;
    }

    write!(
        skel,
        "\
                    _phantom: std::marker::PhantomData<&'obj ()>,
                }}

                impl<'obj> Open{obj_name}Progs<'obj> {{
                    unsafe fn new(
                        object: &mut libbpf_rs::OpenObject,
                    ) -> libbpf_rs::Result<Self> {{
        ",
    )?;

    for name in progs.iter() {
        writeln!(skel, "let mut {name} = None;")?;
    }

    write!(
        skel,
        "\
                        let object = unsafe {{
                            std::mem::transmute::<&mut libbpf_rs::OpenObject, &'obj mut libbpf_rs::OpenObject>(object)
                        }};
                        for prog in object.progs_mut() {{
                            let name = prog
                                .name()
                                .to_str()
                                .ok_or_else(|| {{
                                    libbpf_rs::Error::from(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        \"prog has invalid name\",
                                    ))
                                }})?;
                            match name {{
        ",
    )?;

    for name in progs.iter() {
        writeln!(skel, "      \"{name}\" => {name} = Some(prog),")?;
    }

    write!(
        skel,
        "\
                                _ => panic!(\"encountered unexpected prog: `{{name}}`\"),
                            }}
                        }}

                        let slf = Self {{
        ",
    )?;

    for name in progs.iter() {
        write!(
            skel,
            "\
                            {name}: {name}.expect(\"prog `{name}` not present\"),
            ",
        )?;
    }

    write!(
        skel,
        "\
                            _phantom: std::marker::PhantomData,
                        }};
                        Ok(slf)
                    }}
                }}
        ",
    )?;
    Ok(())
}

fn gen_skel_prog_defs(skel: &mut String, progs: &ProgsData, raw_obj_name: &str) -> Result<()> {
    let obj_name = capitalize_first_letter(raw_obj_name);
    write!(
        skel,
        "\
                pub struct {obj_name}Progs<'obj> {{
        ",
    )?;

    for name in progs.iter() {
        write!(
            skel,
            "\
                    pub {name}: libbpf_rs::ProgramMut<'obj>,
            ",
        )?;
    }

    write!(
        skel,
        "\
                    _phantom: std::marker::PhantomData<&'obj ()>,
                }}

                impl<'obj> {obj_name}Progs<'obj> {{
                    #[allow(unused_variables)]
                    fn new(open_progs: Open{obj_name}Progs<'obj>) -> Self {{
                        Self {{
        ",
    )?;

    for name in progs.iter() {
        write!(
            skel,
            "\
                            {name}: unsafe {{
                                libbpf_rs::ProgramMut::new_mut(open_progs.{name}.as_libbpf_object().as_mut())
                            }},
            ",
        )?;
    }

    write!(
        skel,
        "\
                            _phantom: std::marker::PhantomData,
                        }}
                    }}
                }}
        ",
    )?;
    Ok(())
}


fn gen_skel_types(
    skel: &mut String,
    btf: Option<&GenBtf<'_>>,
    processed: &mut HashSet<TypeId>,
) -> Result<()> {
    let btf = if let Some(btf) = btf {
        btf
    } else {
        return Ok(());
    };

    for ty_id in 1..btf.len() {
        let ty_id = TypeId::from(ty_id as u32);
        // SANITY: A type with this ID should always exist given that BTF IDs
        //         are fully populated up to `len`. Conversion to `BtfType` is
        //         always infallible.
        let ty = btf.type_by_id::<BtfType<'_>>(ty_id).unwrap();

        let sec_def = btf.type_definition(ty, processed)?;
        write!(skel, "{sec_def}")?;
    }
    Ok(())
}

fn gen_skel_struct_ops_getters(skel: &mut String, object: &Object) -> Result<()> {
    if maps(object).next().is_none() {
        return Ok(());
    }

    write!(
        skel,
        "\
        pub fn struct_ops_raw(&self) -> *const StructOps {{
            &self.struct_ops
        }}

        pub fn struct_ops(&self) -> &StructOps {{
            &self.struct_ops
        }}
        ",
    )?;

    Ok(())
}

fn gen_skel_link_defs(skel: &mut String, object: &Object, obj_name: &str) -> Result<()> {
    if object.progs().next().is_none() {
        return Ok(());
    }

    write!(
        skel,
        "\
        #[derive(Default)]
        pub struct {obj_name}Links {{
        ",
    )?;

    for prog in object.progs() {
        writeln!(
            skel,
            "pub {}: Option<libbpf_rs::Link>,",
            get_prog_name(&prog)?
        )?;
    }

    writeln!(skel, "}}")?;

    Ok(())
}

fn gen_skel_link_getter(skel: &mut String, object: &Object, obj_name: &str) -> Result<()> {
    if object.progs().next().is_none() {
        return Ok(());
    }

    writeln!(skel, "pub links: {obj_name}Links,")?;
    Ok(())
}

fn open_bpf_object(name: &str, data: &[u8]) -> Result<Object> {
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

    let obj = unsafe { Object::from_ptr(ptr::NonNull::new(object).unwrap()) };
    Ok(obj)
}

fn gen_skel_attach(skel: &mut String, object: &Object, obj_name: &str) -> Result<()> {
    if object.progs().next().is_none() {
        return Ok(());
    }

    write!(
        skel,
        "\
        fn attach(&mut self) -> libbpf_rs::Result<()> {{
            let skel_ptr = self.skel_config.as_libbpf_object().as_ptr();
            let ret = unsafe {{ libbpf_sys::bpf_object__attach_skeleton(skel_ptr) }};
            if ret != 0 {{
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }}

            self.links = {obj_name}Links {{
        ",
    )?;

    for (idx, prog) in object.progs().enumerate() {
        let prog_name = get_prog_name(&prog)?;

        write!(
            skel,
            "{prog_name}: core::ptr::NonNull::new(self.skel_config.prog_link_ptr({idx})?)
                        .map(|ptr| unsafe {{ libbpf_rs::Link::from_ptr(ptr) }}),
            "
        )?;
    }

    write!(
        skel,
        "
            }};

            Ok(())
        }}
        ",
    )?;

    Ok(())
}

fn gen_skel_struct_ops_init(object: &Object) -> Result<String> {
    let mut def = String::new();

    for map in maps(object) {
        let type_ = map.map_type();
        if type_ != MapType::StructOps {
            continue;
        }

        let raw_name = get_raw_map_name(&map)?;

        write!(
            def,
            "\
            skel.struct_ops.{raw_name} = skel.maps.{raw_name}.initial_value_mut().unwrap().as_mut_ptr().cast();
            ",
        )?;
    }
    Ok(def)
}

/// Generate contents of a single skeleton
fn gen_skel_contents(_debug: bool, raw_obj_name: &str, obj_file_path: &Path) -> Result<String> {
    let mut skel = String::new();

    write!(
        skel,
        "\
        // SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
        //
        // THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

        pub use self::imp::*;

        #[allow(dead_code)]
        #[allow(non_snake_case)]
        #[allow(non_camel_case_types)]
        #[allow(clippy::absolute_paths)]
        #[allow(clippy::upper_case_acronyms)]
        #[allow(clippy::zero_repeat_side_effects)]
        #[warn(single_use_lifetimes)]
        mod imp {{
        #[allow(unused_imports)]
        use super::*;
        use libbpf_rs::libbpf_sys;
        use libbpf_rs::skel::OpenSkel;
        use libbpf_rs::skel::Skel;
        use libbpf_rs::skel::SkelBuilder;
        use libbpf_rs::AsRawLibbpf as _;
        use libbpf_rs::MapCore as _;
        "
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
    let object = open_bpf_object(&libbpf_obj_name, &mmap)?;
    let btf =
        Btf::from_bpf_object(unsafe { object.as_libbpf_object().as_ref() })?.map(GenBtf::from);
    let maps = MapsData::new(&object)?;
    let progs = ProgsData::new(&object)?;

    gen_skel_c_skel_constructor(&mut skel, &object, &libbpf_obj_name)?;
    gen_skel_map_defs(&mut skel, &maps, raw_obj_name, true)?;
    gen_skel_map_defs(&mut skel, &maps, raw_obj_name, false)?;
    gen_skel_open_prog_defs(&mut skel, &progs, raw_obj_name)?;
    gen_skel_prog_defs(&mut skel, &progs, raw_obj_name)?;

    #[allow(clippy::uninlined_format_args)]
    write!(
        skel,
        "\
        struct OwnedRef<'obj, O> {{
            object: Option<&'obj mut std::mem::MaybeUninit<O>>,
        }}

        impl<'obj, O> OwnedRef<'obj, O> {{
            /// # Safety
            /// The object has to be initialized.
            unsafe fn new(object: &'obj mut std::mem::MaybeUninit<O>) -> Self {{
                Self {{
                    object: Some(object),
                }}
            }}

            fn as_ref(&self) -> &O {{
                // SAFETY: As per the contract during construction, the
                //         object has to be initialized.
                unsafe {{ self.object.as_ref().unwrap().assume_init_ref() }}
            }}

            fn as_mut(&mut self) -> &mut O {{
                // SAFETY: As per the contract during construction, the
                //         object has to be initialized.
                unsafe {{ self.object.as_mut().unwrap().assume_init_mut() }}
            }}

            fn take(mut self) -> &'obj mut std::mem::MaybeUninit<O> {{
                self.object.take().unwrap()
            }}
        }}

        impl<O> Drop for OwnedRef<'_, O> {{
            fn drop(&mut self) {{
                if let Some(object) = &mut self.object {{
                    unsafe {{ object.assume_init_drop() }}
                }}
            }}
        }}

        #[derive(Default)]
        pub struct {name}SkelBuilder {{
            pub obj_builder: libbpf_rs::ObjectBuilder,
        }}

        impl<'obj> {name}SkelBuilder {{
            fn open_opts_impl(
                self,
                open_opts: *const libbpf_sys::bpf_object_open_opts,
                object: &'obj mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
            ) -> libbpf_rs::Result<Open{name}Skel<'obj>> {{
                let skel_config = build_skel_config()?;
                let skel_ptr = skel_config.as_libbpf_object();

                let ret = unsafe {{ libbpf_sys::bpf_object__open_skeleton(skel_ptr.as_ptr(), open_opts) }};
                if ret != 0 {{
                    return Err(libbpf_rs::Error::from_raw_os_error(-ret));
                }}

                // SAFETY: `skel_ptr` points to a valid object after the
                //         open call.
                let obj_ptr = unsafe {{ *skel_ptr.as_ref().obj }};
                // SANITY: `bpf_object__open_skeleton` should have
                //         allocated the object.
                let obj_ptr = std::ptr::NonNull::new(obj_ptr).unwrap();
                // SAFETY: `obj_ptr` points to an opened object after
                //         skeleton open.
                let obj = unsafe {{ libbpf_rs::OpenObject::from_ptr(obj_ptr) }};
                let _obj = object.write(obj);
                // SAFETY: We just wrote initialized data to `object`.
                let mut obj_ref = unsafe {{ OwnedRef::new(object) }};

                #[allow(unused_mut)]
                let mut skel = Open{name}Skel {{
                    maps: unsafe {{ Open{name}Maps::new(&skel_config, obj_ref.as_mut())? }},
                    progs: unsafe {{ Open{name}Progs::new(obj_ref.as_mut())? }},
                    obj: obj_ref,
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
        }}

        impl<'obj> SkelBuilder<'obj> for {name}SkelBuilder {{
            type Output = Open{name}Skel<'obj>;
            fn open(
                self,
                object: &'obj mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
            ) -> libbpf_rs::Result<Open{name}Skel<'obj>> {{
                self.open_opts_impl(std::ptr::null(), object)
            }}

            fn open_opts(
                self,
                open_opts: libbpf_sys::bpf_object_open_opts,
                object: &'obj mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
            ) -> libbpf_rs::Result<Open{name}Skel<'obj>> {{
                self.open_opts_impl(&open_opts, object)
            }}

            fn object_builder(&self) -> &libbpf_rs::ObjectBuilder {{
                &self.obj_builder
            }}
            fn object_builder_mut(&mut self) -> &mut libbpf_rs::ObjectBuilder {{
                &mut self.obj_builder
            }}
        }}
        ",
        name = obj_name,
        struct_ops_init = gen_skel_struct_ops_init(&object)?,
    )?;

    let mut processed = HashSet::new();
    // Generate struct_ops types before anything else, as they are slightly
    // modified compared to the dumb structure contained in BTF.
    if let Some(btf) = &btf {
        let gen = GenStructOps::new(btf)?;
        let () = gen.gen_struct_ops_def(&mut skel)?;
        write!(
            skel,
            "\
                pub mod types {{
                    #[allow(unused_imports)]
                    use super::*;
            "
        )?;

        let () = gen.gen_dependent_types(&mut processed, &mut skel)?;
    } else {
        write!(
            skel,
            "
#[derive(Debug, Clone)]
#[repr(C)]
pub struct StructOps {{}}
"
        )?;
        write!(
            skel,
            "\
                pub mod types {{
                    #[allow(unused_imports)]
                    use super::*;
            "
        )?;
    }

    gen_skel_types(&mut skel, btf.as_ref(), &mut processed)?;
    writeln!(skel, "}}")?;

    write!(
        skel,
        "\
        pub struct Open{name}Skel<'obj> {{
            obj: OwnedRef<'obj, libbpf_rs::OpenObject>,
            pub maps: Open{name}Maps<'obj>,
            pub progs: Open{name}Progs<'obj>,
            pub struct_ops: StructOps,
            skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'obj>,
        }}

        impl<'obj> OpenSkel<'obj> for Open{name}Skel<'obj> {{
            type Output = {name}Skel<'obj>;
            fn load(self) -> libbpf_rs::Result<{name}Skel<'obj>> {{
                let skel_ptr = self.skel_config.as_libbpf_object().as_ptr();

                let ret = unsafe {{ libbpf_sys::bpf_object__load_skeleton(skel_ptr) }};
                if ret != 0 {{
                    return Err(libbpf_rs::Error::from_raw_os_error(-ret));
                }}

                let obj_ref = self.obj.take();
                let open_obj = std::mem::replace(obj_ref, std::mem::MaybeUninit::uninit());
                // SAFETY: `open_obj` is guaranteed to be properly
                //         initialized as it came from an `OwnedRef`.
                let obj_ptr = unsafe {{ open_obj.assume_init().take_ptr() }};
                // SAFETY: `obj_ptr` points to a loaded object after
                //         skeleton load.
                let obj = unsafe {{ libbpf_rs::Object::from_ptr(obj_ptr) }};
                // SAFETY: `OpenObject` and `Object` are guaranteed to
                //         have the same memory layout.
                let obj_ref = unsafe {{
                    std::mem::transmute::<
                        &'obj mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
                        &'obj mut std::mem::MaybeUninit<libbpf_rs::Object>,
                    >(obj_ref)
                }};
                let _obj = obj_ref.write(obj);
                // SAFETY: We just wrote initialized data to `obj_ref`.
                let mut obj_ref = unsafe {{ OwnedRef::new(obj_ref) }};

                Ok({name}Skel {{
                    maps: unsafe {{ {name}Maps::new(&self.skel_config, obj_ref.as_mut())? }},
                    progs: {name}Progs::new(self.progs),
                    obj: obj_ref,
                    struct_ops: self.struct_ops,
                    skel_config: self.skel_config,
                    {links}
                }})
            }}

            fn open_object(&self) -> &libbpf_rs::OpenObject {{
                self.obj.as_ref()
            }}

            fn open_object_mut(&mut self) -> &mut libbpf_rs::OpenObject {{
                self.obj.as_mut()
            }}
        ",
        name = &obj_name,
        links = if object.progs().next().is_some() {
            format!("links: {obj_name}Links::default()")
        } else {
            "".to_string()
        }
    )?;
    writeln!(skel, "}}")?;

    gen_skel_link_defs(&mut skel, &object, &obj_name)?;

    write!(
        skel,
        "\
        pub struct {name}Skel<'obj> {{
            obj: OwnedRef<'obj, libbpf_rs::Object>,
            pub maps: {name}Maps<'obj>,
            pub progs: {name}Progs<'obj>,
            struct_ops: StructOps,
            skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'obj>,
        ",
        name = &obj_name,
    )?;
    gen_skel_link_getter(&mut skel, &object, &obj_name)?;
    write!(
        skel,
        "\
        }}

        unsafe impl Send for {name}Skel<'_> {{}}
        unsafe impl Sync for {name}Skel<'_> {{}}

        impl<'obj> Skel<'obj> for {name}Skel<'obj> {{
            fn object(&self) -> &libbpf_rs::Object {{
                self.obj.as_ref()
            }}

            fn object_mut(&mut self) -> &mut libbpf_rs::Object {{
                self.obj.as_mut()
            }}
        ",
        name = &obj_name,
    )?;
    gen_skel_attach(&mut skel, &object, &obj_name)?;
    writeln!(skel, "}}")?;

    write!(skel, "impl {name}Skel<'_> {{", name = &obj_name)?;
    gen_skel_struct_ops_getters(&mut skel, &object)?;
    writeln!(skel, "}}")?;

    // Coerce to &[u8] just to be safe, as we'll be using debug formatting
    let bytes: &[u8] = &mmap;
    writeln!(skel, "const DATA: &[u8] = &{bytes:?};")?;
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
        "\
        // SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
        //
        // THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

        "
    )?;

    for obj in objs {
        write!(
            contents,
            "
            #[path = \"{name}.skel.rs\"]
            mod {name}_skel;
            ",
            name = obj.name
        )?;
    }

    for obj in objs {
        writeln!(contents, "pub use {}_skel::*;", obj.name)?;
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
