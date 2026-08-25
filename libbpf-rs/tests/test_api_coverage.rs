//! Guardrail test tracking which public libbpf APIs are wrapped by libbpf-rs.
//!
//! This test does **not** require that every libbpf symbol be wrapped. Instead
//! it pins the current set of *unwrapped* public functions in
//! [`EXPECTED_UNWRAPPED`]. The authoritative list of exported symbols is parsed
//! from the version-matched vendored headers that `libbpf-sys` exposes as the
//! `libbpf_sys::API_HEADERS` constant, and the set of wrapped symbols is derived
//! by scanning the source for `libbpf_sys::` references.
//!
//! When the vendored libbpf is bumped and introduces new APIs, or when a wrapper
//! is added or removed, this test fails and prints exactly what changed. Update
//! [`EXPECTED_UNWRAPPED`] deliberately and double check accuracy of the
//! "API coverage" section in `src/lib.rs` if the set of supported
//! capabilities changed.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Public libbpf functions that libbpf-rs / libbpf-cargo intentionally do not
/// (yet) wrap. Keep sorted; see the "API coverage" section in `src/lib.rs`.
const EXPECTED_UNWRAPPED: &[&str] = &[
    "bpf_btf_get_fd_by_id_opts",
    "bpf_btf_get_info_by_fd",
    "bpf_btf_load",
    "bpf_enable_stats",
    "bpf_link__update_map",
    "bpf_link_create",
    "bpf_link_detach",
    "bpf_link_get_fd_by_id_opts",
    "bpf_link_get_info_by_fd",
    "bpf_link_update",
    "bpf_linker__add_fd",
    "bpf_linker__new_fd",
    "bpf_map__autoattach",
    "bpf_map__btf_key_type_id",
    "bpf_map__btf_value_type_id",
    "bpf_map__delete_elem",
    "bpf_map__exclusive_program",
    "bpf_map__get_next_key",
    "bpf_map__ifindex",
    "bpf_map__inner_map",
    "bpf_map__lookup_and_delete_elem",
    "bpf_map__lookup_elem",
    "bpf_map__map_extra",
    "bpf_map__set_autoattach",
    "bpf_map__set_exclusive_program",
    "bpf_map__update_elem",
    "bpf_map_delete_elem_flags",
    "bpf_map_get_fd_by_id_opts",
    "bpf_map_get_info_by_fd",
    "bpf_map_lookup_and_delete_elem_flags",
    "bpf_obj_pin_opts",
    "bpf_object__btf_fd",
    "bpf_object__destroy_subskeleton",
    "bpf_object__detach_skeleton",
    "bpf_object__find_map_by_name",
    "bpf_object__find_map_fd_by_name",
    "bpf_object__find_program_by_name",
    "bpf_object__gen_loader",
    "bpf_object__kversion",
    "bpf_object__open",
    "bpf_object__open_subskeleton",
    "bpf_object__pin",
    "bpf_object__pin_maps",
    "bpf_object__pin_programs",
    "bpf_object__prepare",
    "bpf_object__prev_map",
    "bpf_object__prev_program",
    "bpf_object__set_kversion",
    "bpf_object__token_fd",
    "bpf_object__unpin",
    "bpf_object__unpin_maps",
    "bpf_object__unpin_programs",
    "bpf_prog_assoc_struct_ops",
    "bpf_prog_attach_opts",
    "bpf_prog_bind_map",
    "bpf_prog_detach",
    "bpf_prog_detach2",
    "bpf_prog_detach_opts",
    "bpf_prog_get_fd_by_id_opts",
    "bpf_prog_get_info_by_fd",
    "bpf_prog_linfo__free",
    "bpf_prog_linfo__lfind",
    "bpf_prog_linfo__lfind_addr_func",
    "bpf_prog_linfo__new",
    "bpf_prog_load",
    "bpf_prog_query",
    "bpf_prog_query_opts",
    "bpf_program__attach_cgroup_opts",
    "bpf_program__attach_freplace",
    "bpf_program__attach_netkit",
    "bpf_program__attach_sockmap",
    "bpf_program__attach_tcx",
    "bpf_program__attach_trace_opts",
    "bpf_program__attach_tracepoint",
    "bpf_program__autoattach",
    "bpf_program__func_info",
    "bpf_program__func_info_cnt",
    "bpf_program__line_info",
    "bpf_program__line_info_cnt",
    "bpf_program__log_buf",
    "bpf_program__set_insns",
    "bpf_program__set_log_buf",
    "bpf_program__unload",
    "bpf_raw_tracepoint_open",
    "bpf_raw_tracepoint_open_opts",
    "bpf_task_fd_query",
    "bpf_token_create",
    "btf__add_array",
    "btf__add_btf",
    "btf__add_const",
    "btf__add_datasec",
    "btf__add_datasec_var_info",
    "btf__add_decl_attr",
    "btf__add_decl_tag",
    "btf__add_enum",
    "btf__add_enum64",
    "btf__add_enum64_value",
    "btf__add_enum_value",
    "btf__add_field",
    "btf__add_float",
    "btf__add_func",
    "btf__add_func_param",
    "btf__add_func_proto",
    "btf__add_fwd",
    "btf__add_int",
    "btf__add_ptr",
    "btf__add_restrict",
    "btf__add_str",
    "btf__add_struct",
    "btf__add_type",
    "btf__add_type_attr",
    "btf__add_type_tag",
    "btf__add_typedef",
    "btf__add_union",
    "btf__add_var",
    "btf__add_volatile",
    "btf__align_of",
    "btf__base_btf",
    "btf__dedup",
    "btf__distill_base",
    "btf__endianness",
    "btf__fd",
    "btf__find_by_name_kind",
    "btf__find_str",
    "btf__load_from_kernel_by_id_split",
    "btf__load_into_kernel",
    "btf__load_module_btf",
    "btf__new",
    "btf__new_empty",
    "btf__new_empty_split",
    "btf__new_split",
    "btf__parse_elf",
    "btf__parse_elf_split",
    "btf__parse_raw",
    "btf__parse_raw_split",
    "btf__parse_split",
    "btf__permute",
    "btf__raw_data",
    "btf__relocate",
    "btf__resolve_size",
    "btf__resolve_type",
    "btf__set_endianness",
    "btf__set_fd",
    "btf__set_pointer_size",
    "btf__str_by_offset",
    "btf_dump__dump_type",
    "btf_dump__dump_type_data",
    "btf_dump__emit_type_decl",
    "btf_dump__free",
    "btf_dump__new",
    "btf_ext__endianness",
    "btf_ext__free",
    "btf_ext__new",
    "btf_ext__raw_data",
    "btf_ext__set_endianness",
    "libbpf_attach_type_by_name",
    "libbpf_bpf_attach_type_str",
    "libbpf_bpf_link_type_str",
    "libbpf_bpf_map_type_str",
    "libbpf_bpf_prog_type_str",
    "libbpf_find_vmlinux_btf_id",
    "libbpf_major_version",
    "libbpf_minor_version",
    "libbpf_prog_type_by_name",
    "libbpf_register_prog_handler",
    "libbpf_set_memlock_rlim",
    "libbpf_strerror",
    "libbpf_unregister_prog_handler",
    "libbpf_version_string",
    "perf_buffer__buffer",
    "perf_buffer__new_raw",
    "ring__avail_data_size",
    "ring__consume",
    "ring__consume_n",
    "ring__consumer_pos",
    "ring__map_fd",
    "ring__producer_pos",
    "ring__size",
    "ring_buffer__ring",
    "user_ring_buffer__reserve_blocking",
];

/// Source roots scanned for `libbpf_sys::<symbol>` references.
const SOURCE_ROOTS: [&str; 2] = [
    concat!(env!("CARGO_MANIFEST_DIR"), "/src"),
    concat!(env!("CARGO_MANIFEST_DIR"), "/../libbpf-cargo/src"),
];

#[test]
fn coverage_is_current() {
    let exported = exported_symbols();
    let wrapped = wrapped_symbols();
    let unwrapped = exported
        .difference(&wrapped)
        .cloned()
        .collect::<BTreeSet<String>>();
    let expected = EXPECTED_UNWRAPPED
        .iter()
        .map(|symbol| (*symbol).to_string())
        .collect::<BTreeSet<String>>();

    eprintln!(
        "libbpf API coverage: {} exported, {} wrapped, {} unwrapped",
        exported.len(),
        exported.len() - unwrapped.len(),
        unwrapped.len(),
    );

    let newly_unwrapped = unwrapped.difference(&expected).collect::<Vec<_>>();
    let newly_wrapped = expected.difference(&unwrapped).collect::<Vec<_>>();

    if newly_unwrapped.is_empty() && newly_wrapped.is_empty() {
        return;
    }

    let mut message = format!(
        "libbpf API coverage drift detected: {} exported, {} wrapped, {} unwrapped\n",
        exported.len(),
        exported.len() - unwrapped.len(),
        unwrapped.len(),
    );
    if !newly_unwrapped.is_empty() {
        message.push_str("\nNew unwrapped symbols (wrap them, or add to EXPECTED_UNWRAPPED):\n");
        for symbol in &newly_unwrapped {
            message.push_str(&format!("    {symbol}\n"));
        }
    }
    if !newly_wrapped.is_empty() {
        message.push_str("\nNow wrapped (remove from EXPECTED_UNWRAPPED):\n");
        for symbol in &newly_wrapped {
            message.push_str(&format!("    {symbol}\n"));
        }
    }
    message.push_str(
        "\nAlso refresh the \"API coverage\" section in src/lib.rs if capabilities changed.\n",
    );

    panic!("{message}");
}

/// Collect every `libbpf_sys::<symbol>` identifier referenced under the source
/// roots. This also catches `use libbpf_sys::<symbol>;` imports.
fn wrapped_symbols() -> BTreeSet<String> {
    let mut wrapped = BTreeSet::new();
    for root in SOURCE_ROOTS {
        collect_refs(Path::new(root), &mut wrapped);
    }
    wrapped
}

fn collect_refs(dir: &Path, out: &mut BTreeSet<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_refs(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            if let Ok(source) = fs::read_to_string(&path) {
                scan_refs(&source, out);
            }
        }
    }
}

fn scan_refs(source: &str, out: &mut BTreeSet<String>) {
    const PATTERN: &str = "libbpf_sys::";
    let mut rest = source;
    while let Some(pos) = rest.find(PATTERN) {
        let after = &rest[pos + PATTERN.len()..];
        let name = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<String>();
        rest = &after[name.len()..];
        if !name.is_empty() {
            out.insert(name);
        }
    }
}

/// Parse the public libbpf API (every `LIBBPF_API` function) out of the headers
/// vendored by `libbpf-sys` and exposed via `libbpf_sys::API_HEADERS`.
fn exported_symbols() -> BTreeSet<String> {
    let mut symbols = BTreeSet::new();
    for (_name, contents) in libbpf_sys::API_HEADERS {
        let source = strip_comments(contents);
        // Every exported function is introduced by the `LIBBPF_API` macro and
        // ends at the first `;`. The declaration may span multiple lines.
        for decl in source.split("LIBBPF_API").skip(1) {
            let decl = decl.split(';').next().unwrap_or_default();
            if let Some(name) = extract_fn_name(decl) {
                symbols.insert(name);
            }
        }
    }
    symbols
}

/// Strip C block and line comments so they cannot be mistaken for declarations.
fn strip_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                i += 1;
            }
            i += 2;
            out.push(' ');
        } else if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else {
            // Headers are ASCII; anything else lives only in comments.
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Extract the libbpf function name from a declaration (text up to the `;`).
///
/// The name is the identifier immediately preceding the first `(` that forms a
/// libbpf-style symbol. Scanning successive `(`s makes this robust against
/// deprecation macros (e.g. `LIBBPF_DEPRECATED_SINCE(...)`) appearing before the
/// name.
fn extract_fn_name(decl: &str) -> Option<String> {
    let bytes = decl.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'(' {
            continue;
        }
        let mut end = i;
        while end > 0 && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        let mut start = end;
        while start > 0 && is_ident_byte(bytes[start - 1]) {
            start -= 1;
        }
        if start < end {
            let name = &decl[start..end];
            if is_libbpf_symbol(name) {
                return Some(name.to_string());
            }
        }
    }
    None
}

fn is_ident_byte(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

/// Whether `name` looks like an exported libbpf function (lowercase, known
/// prefix), as opposed to a macro or type.
fn is_libbpf_symbol(name: &str) -> bool {
    matches!(name.as_bytes().first(), Some(b'a'..=b'z'))
        && [
            "bpf",
            "btf",
            "libbpf",
            "perf_buffer",
            "ring",
            "ring_buffer",
            "user_ring_buffer",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}
