use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/netfilter_blocklist.bpf.c";

fn main() {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("netfilter_blocklist.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-Wno-compare-distinct-pointer-types"),
            OsStr::new("-I"),
        ])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
