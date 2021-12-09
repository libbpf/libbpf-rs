# libbpf-rs tests

libbpf-rs tests are designed to be independent of libbpf-cargo and underlying
compiler versions. To that end, we check in pre-compiled bpf object files in
`libbpf-rs/tests/bin`. To help with writing new tests, the original source
code for the pre-compiled objects are placed in `libbpf-rs/tests/bin/src`.

To regenerate the test bpf object files 
run bpf_object_regen.sh script via the command:
$ ./bpf_object_regen.sh

The script bpf_object_regen.sh depends on the following packages installed:

bash
bpftool (optional)
clang
libbpf

Installation Instructions for common distributions

Ubuntu 21.10+: (should work with 20.10+ (untested), 20.04 will not work!!)
required:
$ apt install bash clang libbpf-dev
optional:
$ apt install linux-tools-generic
Note: bin/src/runqslower.bpf.c requires a vmlinux.h generated from kernel 5.14+

Debian 11+:
required:
$ apt install bash clang libbpf-dev
optional:
$ apt install bpftool
Note: bin/src/runqslower.bpf.c requires a vmlinux.h generated from kernel 5.14+
Note: requires running with 
$ PATH=$PATH:/usr/sbin/ ./bpf_object_regen.sh -b ...

Arch Linux: (tested as of 2021/12/16)
required:
$ pacman -S bash clang libbpf
optional:
$ pacman -S bpf

Fedora 35+, Centos Stream 9: (should work with Fedora 34 (untested), RHEL 9 (untested))
required:
$ dnf install bash clang libbpf-devel
optional:
$ dnf install bpftool

Alma Linux 8.5+: (should work with Centos-Stream-8 (untested) and derivatives eg RHEL 8.5 (untested))
required:
$ dnf install epel-release
$ dnf --enablerepo=powertools install bash clang libbpf-devel
optional:
$ dnf install bpftool
Note: bin/src/runqslower.bpf.c requires a vmlinux.h generated from kernel 5.14+

