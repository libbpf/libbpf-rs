use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

const SRC: &str = "src/bpf/runqslower.bpf.c";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("runqslower.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={}", SRC);
}
