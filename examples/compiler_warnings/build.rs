use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::util::CargoWarningFormatter;
use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/compiler_warnings.bpf.c";


fn main() {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("compiler_warnings.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    // Set the global subscriber emitting cargo:warning lines for
    // emitted compiler output. In settings other than build scripts you
    // may want to resort to just setting the subscriber temporarily,
    // with something like `tracing::subscriber::with_default`.
    let () = tracing_subscriber::fmt()
        .event_format(CargoWarningFormatter)
        .init();

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
        ])
        .build_and_generate(&out)
        .unwrap();

    println!("cargo:rerun-if-changed={SRC}");
}
