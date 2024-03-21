#![allow(non_upper_case_globals)]

use std::env::consts::ARCH;
use std::path::Path;
use std::path::PathBuf;

// TODO: Ideally we'd deduplicate contents at this level (as well; not just on
//       the file system).
/// The contents of `vmlinux.h` for `aarch64`.
pub static VMLINUX_aarch64: &[u8] = include_bytes!("../include/aarch64/vmlinux.h");
/// The contents of `vmlinux.h` for `arm`.
pub static VMLINUX_arm: &[u8] = include_bytes!("../include/arm/vmlinux.h");
/// The contents of `vmlinux.h` for `loongarch64`.
pub static VMLINUX_loongarch64: &[u8] = include_bytes!("../include/loongarch64/vmlinux.h");
/// The contents of `vmlinux.h` for `powerpc`.
pub static VMLINUX_powerpc: &[u8] = include_bytes!("../include/powerpc/vmlinux.h");
/// The contents of `vmlinux.h` for `riscv64`.
pub static VMLINUX_riscv64: &[u8] = include_bytes!("../include/riscv64/vmlinux.h");
/// The contents of `vmlinux.h` for `x86`.
pub static VMLINUX_x86: &[u8] = include_bytes!("../include/x86/vmlinux.h");
/// The contents of `vmlinux.h` for `x86_64`.
pub static VMLINUX_x86_64: &[u8] = include_bytes!("../include/x86_64/vmlinux.h");

// TODO: Unsafe code should be replaced with safe alternatives once stable.
macro_rules! check_and_advance {
    ($args:ident) => {{
        let (mut p1, mut p2, mut remaining_len) = $args;
        if remaining_len == 0 {
            return true;
        }

        if unsafe { p1.read() } != unsafe { p2.read() } {
            return false;
        }

        p1 = unsafe { p1.add(1) };
        p2 = unsafe { p2.add(1) };
        remaining_len -= 1;

        (p1, p2, remaining_len)
    }};
}

/// A string equality check usable in `const` contexts.
const fn eq(s1: &str, s2: &str) -> bool {
    if s1.len() != s2.len() {
        return false;
    }

    let len = s1.len();
    let p1 = s1.as_bytes().as_ptr();
    let p2 = s2.as_bytes().as_ptr();
    let mut args = (p1, p2, len);

    // Longest `std::env::consts::ARCH` string is ten characters, so we should
    // be good.
    args = check_and_advance!(args);
    args = check_and_advance!(args);
    args = check_and_advance!(args);
    args = check_and_advance!(args);
    args = check_and_advance!(args);
    args = check_and_advance!(args);
    args = check_and_advance!(args);
    args = check_and_advance!(args);
    args = check_and_advance!(args);
    args = check_and_advance!(args);
    args = check_and_advance!(args);
    _ = check_and_advance!(args);

    panic!("maximum supported string length exceeded; go and copy & paste some more");
}

/// The contents of `vmlinux.h` for the target architecture.
pub static VMLINUX: &[u8] = {
    // We may end up being invoked by a build script, in which case
    // `CARGO_CFG_TARGET_ARCH` would represent the target architecture. It
    // should not be set in other contexts.
    let arch = if let Some(arch) = option_env!("CARGO_CFG_TARGET_ARCH") {
        arch
    } else {
        ARCH
    };

    if eq(arch, "x86") {
        VMLINUX_x86
    } else if eq(arch, "x86_64") {
        VMLINUX_x86_64
    } else if eq(arch, "arm") {
        VMLINUX_arm
    } else if eq(arch, "aarch64") {
        VMLINUX_aarch64
    } else if eq(arch, "loongarch64") {
        VMLINUX_loongarch64
    } else if eq(arch, "powerpc") {
        VMLINUX_powerpc
    } else {
        panic!("your architecture is not currently supported")
    }
};

/// Retrieve the root of the directory containing architecture specific
/// directories containing `vmlinux.h` files. E.g., in a hierarchy:
/// ```text
/// .
/// └── include
///     ├── aarch64
///     │   └── vmlinux.h
///     ├── arm
///     │   └── vmlinux.h
///     ├── loongarch64
///     │   └── vmlinux.h
///     ├── powerpc
///     │   └── vmlinux.h
///     ├── riscv64
///     │   └── vmlinux.h
///     ├── x86
///     │   └── vmlinux.h
///     └── x86_64 -> x86
/// ```
/// this function would return the absolute path to `include/`.
///
/// # Examples
/// ```
/// use std::env::consts::ARCH;
///
/// assert!(vmlinux::include_path_root()
///     .join(ARCH)
///     .join("vmlinux.h")
///     .try_exists()
///     .unwrap());
/// ```
#[inline]
pub fn include_path_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("include")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Check that our `eq` function works as it should.
    #[test]
    fn equality_check() {
        assert!(!eq("foobar", "foobaz"));
        assert!(eq("foobar", "foobar"));
        let s = "&*!@)&*$@&";
        assert!(eq(s, s));
        let s = "loongarch64";
        assert!(eq(s, s));
    }

    /// Check that the `eq` function handles excessively long string as expected.
    #[test]
    #[should_panic = "maximum supported string length exceeded"]
    fn overly_long_equality_check() {
        let s = "abcdefghijklmn";
        assert!(eq(s, s));
    }

    /// That that the reported include path is kosher.
    #[test]
    fn include_path_existence() {
        assert!(include_path_root()
            .join(ARCH)
            .join("vmlinux.h")
            .try_exists()
            .unwrap())
    }
}
