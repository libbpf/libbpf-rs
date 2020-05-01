# libbpf-rs tests

libbpf-rs tests are designed to be independent of libbpf-cargo and underlying
compiler versions. To that end, we check in pre-compiled bpf object files in
`libbpf-rs/tests/bin`. To help with writing new tests, the original source
code for the pre-compiled objects are placed in `libbpf-rs/tests/bin/src`.
