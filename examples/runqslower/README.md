# runqslower-rs

`runqslower-rs` provides a canonical example on how to use `libbpf-cargo` and `libbpf-rs`
effectively.

---

To build the project:
```shell
$ cd examples/runqslower
$ cargo build
$ sudo ../../target/debug/runqslower 1000
Tracing run queue latency higher than 1000 us
TIME     COMM             TID     LAT(us)
13:40:58 WebExtensions    961211  1287
13:40:58 WebExtensions    961211  1516
13:40:58 Timer            961076  2255
13:40:58 AudioIPC0        1111261 2375
13:40:58 Gecko_IOThread   961074  2252
13:40:58 WebExtensions    961211  1030
^C
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
