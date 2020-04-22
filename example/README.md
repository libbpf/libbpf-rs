# runqslower-rs

`runqslower-rs` provides a canonical example on how to use `libbpf-cargo` and `libbpf-rs`
effectively.

---

To build the project:
```shell
$ pwd
/home/daniel/dev/libbpf-rs/example
$ cargo libbpf build
$ cargo build
$ # XXX tbd
```

---

To generate an updated `vmlinux.h`:
```shell
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./vmlinux.h
```

BTF might also be found at `/boot/vmlinux-$(uname -r)`, depending on which
linux distribution you run.

You can see if your kernel is compiled with BTF by running:
```shell
$ zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz
```
