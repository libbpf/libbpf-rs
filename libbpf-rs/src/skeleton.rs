use core::ffi::c_void;
use std::alloc::alloc_zeroed;
use std::alloc::dealloc;
use std::alloc::Layout;
use std::boxed::Box;
use std::ffi::CString;
use std::mem::size_of;
use std::os::raw::c_char;
use std::os::raw::c_ulong;
use std::ptr;
use std::ptr::NonNull;

use libbpf_sys::bpf_link;
use libbpf_sys::bpf_map;
use libbpf_sys::bpf_map_skeleton;
use libbpf_sys::bpf_object;
use libbpf_sys::bpf_object_skeleton;
use libbpf_sys::bpf_prog_skeleton;
use libbpf_sys::bpf_program;

use crate::error::IntoError as _;
use crate::libbpf_sys;
use crate::util;
use crate::Error;
use crate::Object;
use crate::ObjectBuilder;
use crate::OpenObject;
use crate::Result;

#[derive(Debug)]
struct MapSkelConfig {
    name: String,
    p: Box<*mut bpf_map>,
    mmaped: Option<Box<*mut c_void>>,
}

#[derive(Debug)]
struct ProgSkelConfig {
    name: String,
    p: Box<*mut bpf_program>,
    link: Box<*mut bpf_link>,
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct ObjectSkeletonConfigBuilder<'a> {
    data: &'a [u8],
    p: Box<*mut bpf_object>,
    name: Option<String>,
    maps: Vec<MapSkelConfig>,
    progs: Vec<ProgSkelConfig>,
}

fn str_to_cstring_and_pool(s: &str, pool: &mut Vec<CString>) -> Result<*const c_char> {
    let cname = util::str_to_cstring(s)?;
    let p = cname.as_ptr();
    pool.push(cname);

    Ok(p)
}

impl<'a> ObjectSkeletonConfigBuilder<'a> {
    /// Construct a new instance
    ///
    /// `object_data` is the contents of the `.o` from clang
    ///
    /// `p` is a reference to the pointer where `libbpf_sys::bpf_object` should be
    /// stored/retrieved
    pub fn new(object_data: &'a [u8]) -> Self {
        Self {
            data: object_data,
            p: Box::new(ptr::null_mut()),
            name: None,
            maps: Vec::new(),
            progs: Vec::new(),
        }
    }

    #[allow(missing_docs)]
    pub fn name<T: AsRef<str>>(&mut self, name: T) -> &mut Self {
        self.name = Some(name.as_ref().to_string());
        self
    }

    /// Adds a map to the config
    ///
    /// Set `mmaped` to `true` if the map is mmap'able to userspace
    pub fn map<T: AsRef<str>>(&mut self, name: T, mmaped: bool) -> &mut Self {
        let m = if mmaped {
            Some(Box::new(ptr::null_mut()))
        } else {
            None
        };

        self.maps.push(MapSkelConfig {
            name: name.as_ref().to_string(),
            p: Box::new(ptr::null_mut()),
            mmaped: m,
        });

        self
    }

    /// Adds a prog to the config
    pub fn prog<T: AsRef<str>>(&mut self, name: T) -> &mut Self {
        self.progs.push(ProgSkelConfig {
            name: name.as_ref().to_string(),
            p: Box::new(ptr::null_mut()),
            link: Box::new(ptr::null_mut()),
        });

        self
    }

    fn build_maps(
        maps: &mut [MapSkelConfig],
        s: &mut bpf_object_skeleton,
        string_pool: &mut Vec<CString>,
    ) -> Option<Layout> {
        if maps.is_empty() {
            return None;
        }

        s.map_cnt = maps.len() as i32;
        s.map_skel_sz = size_of::<bpf_map_skeleton>() as i32;

        let layout = Layout::array::<bpf_map_skeleton>(maps.len())
            .expect("Failed to allocate memory for maps skeleton");

        unsafe {
            s.maps = alloc_zeroed(layout) as *mut bpf_map_skeleton;
            for (i, map) in maps.iter_mut().enumerate() {
                let current_map = s.maps.add(i);

                // Opt to panic on error here. We've already allocated memory and we'd rather not
                // leak. Extremely unlikely to have invalid unicode anyways.
                (*current_map).name = str_to_cstring_and_pool(&map.name, string_pool)
                    .expect("Invalid unicode in map name");
                (*current_map).map = &mut *map.p;
                (*current_map).mmaped = if let Some(ref mut mmaped) = map.mmaped {
                    &mut **mmaped
                } else {
                    ptr::null_mut()
                };
            }
        }

        Some(layout)
    }

    fn build_progs(
        progs: &mut [ProgSkelConfig],
        s: &mut bpf_object_skeleton,
        string_pool: &mut Vec<CString>,
    ) -> Option<Layout> {
        if progs.is_empty() {
            return None;
        }

        s.prog_cnt = progs.len() as i32;
        s.prog_skel_sz = size_of::<bpf_prog_skeleton>() as i32;

        let layout = Layout::array::<bpf_prog_skeleton>(progs.len())
            .expect("Failed to allocate memory for progs skeleton");

        unsafe {
            s.progs = alloc_zeroed(layout) as *mut bpf_prog_skeleton;
            for (i, prog) in progs.iter_mut().enumerate() {
                let current_prog = s.progs.add(i);

                // See above for `expect()` rationale
                (*current_prog).name = str_to_cstring_and_pool(&prog.name, string_pool)
                    .expect("Invalid unicode in prog name");
                (*current_prog).prog = &mut *prog.p;
                (*current_prog).link = &mut *prog.link;
            }
        }

        Some(layout)
    }

    #[allow(missing_docs)]
    pub fn build(mut self) -> Result<ObjectSkeletonConfig<'a>> {
        // Holds `CString`s alive so pointers to them stay valid
        let mut string_pool = Vec::new();

        let mut s = libbpf_sys::bpf_object_skeleton {
            sz: size_of::<bpf_object_skeleton>() as c_ulong,
            ..Default::default()
        };

        if let Some(ref n) = self.name {
            s.name = str_to_cstring_and_pool(n, &mut string_pool)?;
        }

        // libbpf_sys will use it as const despite the signature
        s.data = self.data.as_ptr() as *mut c_void;
        s.data_sz = self.data.len() as c_ulong;

        // Give s ownership over the box
        s.obj = Box::into_raw(self.p);

        let maps_layout = Self::build_maps(&mut self.maps, &mut s, &mut string_pool);
        let progs_layout = Self::build_progs(&mut self.progs, &mut s, &mut string_pool);

        Ok(ObjectSkeletonConfig {
            inner: s,
            maps: self.maps,
            progs: self.progs,
            maps_layout,
            progs_layout,
            _data: self.data,
            _string_pool: string_pool,
        })
    }
}

/// Helper struct that wraps a `libbpf_sys::bpf_object_skeleton`.
///
/// This struct will:
/// * ensure lifetimes are valid for dependencies (pointers, data buffer)
/// * free any allocated memory on drop
///
/// This struct can be moved around at will. Upon drop, all allocated resources will be freed
#[derive(Debug)]
pub struct ObjectSkeletonConfig<'a> {
    inner: bpf_object_skeleton,
    maps: Vec<MapSkelConfig>,
    progs: Vec<ProgSkelConfig>,
    /// Layout necessary to `dealloc` memory
    maps_layout: Option<Layout>,
    /// Same as above
    progs_layout: Option<Layout>,
    /// Hold this reference so that compiler guarantees buffer lives as long as us
    _data: &'a [u8],
    /// Hold strings alive so pointers to them stay valid
    _string_pool: Vec<CString>,
}

impl ObjectSkeletonConfig<'_> {
    #[allow(missing_docs)]
    pub fn get(&mut self) -> &mut bpf_object_skeleton {
        &mut self.inner
    }

    /// Warning: the returned pointer is only valid while the `ObjectSkeletonConfig` is alive.
    ///
    /// # Panic
    /// This method panics if the inner [`bpf_object_skeleton`] has not be initialized.
    ///
    /// To initialize it, first call [`Self::get`] and initialize the skeleton.
    pub fn object_ptr(&mut self) -> NonNull<bpf_object> {
        NonNull::new(unsafe { *self.inner.obj }).expect(
            r#"
        The generated code failed to initialize bpf_object_skeleton.obj pointer through the use
        of `bpf_object__open_skeleton(skel_config.get(), &open_opts)`
        "#,
        )
    }

    /// Returns the `mmaped` pointer for a map at the specified `index`.
    ///
    /// The index is determined by the order in which the map was passed to
    /// `ObjectSkeletonConfigBuilder::map`. Index starts at 0.
    ///
    /// Warning: the returned pointer is only valid while the `ObjectSkeletonConfig` is alive.
    pub fn map_mmap_ptr(&self, index: usize) -> Result<*const c_void> {
        if index >= self.maps.len() {
            return Err(Error::with_invalid_data(format!(
                "Invalid map index: {index}"
            )));
        }

        let p = self.maps[index]
            .mmaped
            .as_ref()
            .ok_or_invalid_data(|| "Map does not have mmaped ptr")?;
        Ok(**p)
    }

    /// Returns the `mmaped` pointer for a map at the specified `index`.
    ///
    /// The index is determined by the order in which the map was passed to
    /// `ObjectSkeletonConfigBuilder::map`. Index starts at 0.
    ///
    /// Warning: the returned pointer is only valid while the `ObjectSkeletonConfig` is alive.
    pub fn map_mmap_ptr_mut(&mut self, index: usize) -> Result<*mut c_void> {
        self.map_mmap_ptr(index).map(|p| p.cast_mut())
    }

    /// Returns the link pointer for a prog at the specified `index`.
    ///
    /// The index is determined by the order in which the prog was passed to
    /// `ObjectSkeletonConfigBuilder::prog`. Index starts at 0.
    ///
    /// Warning: the returned pointer is only valid while the `ObjectSkeletonConfig` is alive.
    pub fn prog_link_ptr(&mut self, index: usize) -> Result<*mut bpf_link> {
        if index >= self.progs.len() {
            return Err(Error::with_invalid_data(format!(
                "Invalid prog index: {index}"
            )));
        }

        Ok(*self.progs[index].link)
    }
}

impl Drop for ObjectSkeletonConfig<'_> {
    // Note we do *not* run `libbpf_sys::bpf_object__destroy_skeleton` here.
    //
    // Couple reasons:
    //
    // 1) We did not allocate `libbpf_sys::bpf_object_skeleton` on the heap and
    //    `libbpf_sys::bpf_object__destroy_skeleton` will try to free from heap
    //
    // 2) `libbpf_object_skeleton` assumes it "owns" the object and everything inside it.
    //    libbpf-cargo's generated skeleton instead gives ownership of the object to
    //    libbpf-rs::*Object. The destructors in libbpf-rs::*Object will know when and how to do
    //    cleanup.
    fn drop(&mut self) {
        assert_eq!(self.maps_layout.is_none(), self.inner.maps.is_null());
        assert_eq!(self.progs_layout.is_none(), self.inner.progs.is_null());

        if let Some(layout) = self.maps_layout {
            unsafe {
                dealloc(self.inner.maps as _, layout);
            }
        }

        if let Some(layout) = self.progs_layout {
            unsafe {
                dealloc(self.inner.progs as _, layout);
            }
        }

        let _ = unsafe { Box::from_raw(self.inner.obj) };
    }
}

/// A trait for skeleton builder.
pub trait SkelBuilder<'a> {
    /// Define that when BPF object is opened, the returned type should implement the [`OpenSkel`] trait
    type Output: OpenSkel;

    /// Open eBPF object and return [`OpenSkel`]
    fn open(self) -> Result<Self::Output>;

    /// Open eBPF object with [`libbpf_sys::bpf_object_open_opts`] and return [`OpenSkel`]
    fn open_opts(self, open_opts: libbpf_sys::bpf_object_open_opts) -> Result<Self::Output>;

    /// Get a reference to [`ObjectBuilder`]
    fn object_builder(&self) -> &ObjectBuilder;

    /// Get a mutable reference to [`ObjectBuilder`]
    fn object_builder_mut(&mut self) -> &mut ObjectBuilder;
}

/// A trait for opened skeleton.
///
/// In addition to the methods defined in this trait, skeletons that implement this trait will also
/// have bespoke implementations of a few additional methods to facilitate access to global
/// variables of the BPF program. These methods will be named `bss()`, `data()`, and `rodata()`.
/// Each corresponds to the variables stored in the BPF ELF program section of the same name.
/// However if your BPF program lacks one of these sections the corresponding rust method will not
/// be generated.
///
/// The type of the value returned by each of these methods will be specific to your BPF program.
/// A common convention is to define a single global variable in the BPF program with a struct type
/// containing a field for each configuration parameter <sup>\[[source]\]</sup>.  libbpf-rs
/// auto-generates this pattern for you without you having to define such a struct type in your BPF
/// program. It does this by examining each of the global variables in your BPF program's `.bss`,
/// `.data`, and `.rodata` sections and then creating rust struct types `<yourprogram>_bss_types`,
/// `<yourprogram>_data_types`, and `<yourprogram>_rodata_types`. Since these struct types are
/// specific to the layout of your BPF program, they are not documented in this crate. However you
/// can see documentation for them by running `cargo doc` in your own project and looking at the
/// `imp` module. You can also view their implementation by looking at the generated skeleton rust
/// source file. The use of these methods can also be seen in the examples 'capable', 'runqslower',
/// and 'tproxy'.
///
/// If you ever doubt whether libbpf-rs has placed a particular variable in the correct struct
/// type, you can see which section each global variable is stored in by examing the output of the
/// following command (after a successful build):
///
/// ```sh
/// bpf-objdump --syms ./target/bpf/*.bpf.o
/// ```
///
/// [source]: https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/#application-configuration
pub trait OpenSkel {
    /// Define that when BPF object is loaded, the returned type should implement the [`Skel`] trait
    type Output: Skel;

    /// Load BPF object and return [`Skel`].
    fn load(self) -> Result<Self::Output>;

    /// Get a reference to [`OpenObject`].
    fn open_object(&self) -> &OpenObject;

    /// Get a mutable reference to [`OpenObject`].
    fn open_object_mut(&mut self) -> &mut OpenObject;
}

/// A trait for loaded skeleton.
pub trait Skel {
    /// Attach BPF object.
    fn attach(&mut self) -> Result<()> {
        unimplemented!()
    }
    /// Get a reference to [`Object`].
    fn object(&self) -> &Object;

    /// Get a mutable reference to [`Object`].
    fn object_mut(&mut self) -> &mut Object;
}
