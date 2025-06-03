//! Example illustrating how to query some system BTF information.

use std::ffi::OsStr;

use libbpf_rs::btf;
use libbpf_rs::btf::types;


fn main() {
    let btf = btf::Btf::from_vmlinux().expect("failed to retrieve vmlinux BTF information");
    let task_struct = btf
        .type_by_name::<types::Struct>("task_struct")
        .expect("failed to find `task_struct` in vmlinux BTF");
    println!(
        "struct {:?} has type ID: {}",
        task_struct.name().unwrap(),
        task_struct.type_id()
    );

    // Print names of the first five members, for illustration purposes.
    println!("first five members:");
    for member in task_struct.iter().take(5) {
        println!("\t{:?}", member.name.unwrap_or(OsStr::new("anonymous")));
    }
}
