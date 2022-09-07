use core::ffi::c_void;
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::boxed::Box;
use std::ffi::CString;
use std::mem::size_of;
use std::os::raw::{c_char, c_ulong};
use std::ptr;

use libbpf_sys::{
    bpf_link, bpf_map, bpf_map_skeleton, bpf_object, bpf_object_skeleton, bpf_prog_skeleton,
    bpf_program,
};

use crate::util;
use crate::*;

#[allow(missing_debug_implementations)]
struct MapSkelConfig {
    name: String,
    p: Box<*mut bpf_map>,
    mmaped: Option<Box<*mut c_void>>,
}

#[allow(missing_debug_implementations)]
struct ProgSkelConfig {
    name: String,
    p: Box<*mut bpf_program>,
    link: Box<*mut bpf_link>,
}

#[allow(missing_debug_implementations)]
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
        &mut self,
        s: &mut bpf_object_skeleton,
        string_pool: &mut Vec<CString>,
    ) -> Option<Layout> {
        if self.maps.is_empty() {
            return None;
        }

        s.map_cnt = self.maps.len() as i32;
        s.map_skel_sz = size_of::<bpf_map_skeleton>() as i32;

        let layout = Layout::array::<bpf_map_skeleton>(self.maps.len())
            .expect("Failed to allocate memory for maps skeleton");

        unsafe {
            s.maps = alloc_zeroed(layout) as *mut bpf_map_skeleton;
            for (i, map) in self.maps.iter_mut().enumerate() {
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
        &mut self,
        s: &mut bpf_object_skeleton,
        string_pool: &mut Vec<CString>,
    ) -> Option<Layout> {
        if self.progs.is_empty() {
            return None;
        }

        s.prog_cnt = self.progs.len() as i32;
        s.prog_skel_sz = size_of::<bpf_prog_skeleton>() as i32;

        let layout = Layout::array::<bpf_prog_skeleton>(self.progs.len())
            .expect("Failed to allocate memory for progs skeleton");

        unsafe {
            s.progs = alloc_zeroed(layout) as *mut bpf_prog_skeleton;
            for (i, prog) in self.progs.iter_mut().enumerate() {
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

        s.obj = &mut *self.p;

        let maps_layout = self.build_maps(&mut s, &mut string_pool);
        let progs_layout = self.build_progs(&mut s, &mut string_pool);

        Ok(ObjectSkeletonConfig {
            inner: s,
            obj: self.p,
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
#[allow(missing_debug_implementations)]
pub struct ObjectSkeletonConfig<'a> {
    inner: bpf_object_skeleton,
    obj: Box<*mut bpf_object>,
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

impl<'a> ObjectSkeletonConfig<'a> {
    pub fn get(&mut self) -> &mut bpf_object_skeleton {
        &mut self.inner
    }

    /// Warning: the returned pointer is only valid while the `ObjectSkeletonConfig` is alive.
    pub fn object_ptr(&mut self) -> *mut bpf_object {
        *self.obj
    }

    /// Returns the `mmaped` pointer for a map at the specified `index`.
    ///
    /// The index is determined by the order in which the map was passed to
    /// `ObjectSkeletonConfigBuilder::map`. Index starts at 0.
    ///
    /// Warning: the returned pointer is only valid while the `ObjectSkeletonConfig` is alive.
    pub fn map_mmap_ptr(&mut self, index: usize) -> Result<*mut c_void> {
        if index >= self.maps.len() {
            return Err(Error::Internal(format!("Invalid map index: {}", index)));
        }

        self.maps[index].mmaped.as_ref().map_or_else(
            || Err(Error::Internal("Map does not have mmaped ptr".to_string())),
            |p| Ok(**p),
        )
    }

    /// Returns the link pointer for a prog at the specified `index`.
    ///
    /// The index is determined by the order in which the prog was passed to
    /// `ObjectSkeletonConfigBuilder::prog`. Index starts at 0.
    ///
    /// Warning: the returned pointer is only valid while the `ObjectSkeletonConfig` is alive.
    pub fn prog_link_ptr(&mut self, index: usize) -> Result<*mut bpf_link> {
        if index >= self.progs.len() {
            return Err(Error::Internal(format!("Invalid prog index: {}", index)));
        }

        Ok(*self.progs[index].link)
    }
}

impl<'a> Drop for ObjectSkeletonConfig<'a> {
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
    }
}
