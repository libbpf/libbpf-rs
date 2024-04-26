# TCP Header Modification Example
This example focuses on modifying TCP headers, demonstrating how users can extend and manipulate network packet headers as required.

## Building

```shell
$ cargo build
```

## Demo

```shell
$ sudo ./target/debug/tcp_option -i <target>
```
And then send a request to the server.

View the output:
```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```
Output:
```text
<...>-170660  [002] d..21 2056442.479300: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 524, required space: 8
<...>-170660  [002] d..21 2056442.479324: bpf_trace_printk: Stored a TCP option in TCP Flag: 2
<...>-170660  [002] D..41 2056442.479360: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<...>-170660  [002] D..41 2056442.479361: bpf_trace_printk: ####=> Socket TCP option data: 42
<idle>-0       [005] d.s41 2056442.479594: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 1448, required space: 8
<idle>-0       [005] d.s41 2056442.479621: bpf_trace_printk: Stored a TCP option in TCP Flag: 16
<idle>-0       [005] D.s61 2056442.479632: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<idle>-0       [005] D.s61 2056442.479634: bpf_trace_printk: ####=> Socket TCP option data: 42
curl-170660  [002] d..21 2056442.479666: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 1448, required space: 8
curl-170660  [002] d..21 2056442.479681: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 1448, required space: 86
curl-170660  [002] d..21 2056442.479683: bpf_trace_printk: Stored a TCP option in TCP Flag: 24
curl-170660  [002] D..41 2056442.479690: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
curl-170660  [002] D..41 2056442.479701: bpf_trace_printk: ####=> Socket TCP option data: 42
<idle>-0       [005] d.s41 2056442.479984: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 1448, required space: 8
<idle>-0       [005] d.s41 2056442.480005: bpf_trace_printk: Stored a TCP option in TCP Flag: 16
<idle>-0       [005] D.s61 2056442.480014: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<idle>-0       [005] D.s61 2056442.480016: bpf_trace_printk: ####=> Socket TCP option data: 42
curl-170660  [002] d..21 2056442.480212: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 1448, required space: 8
curl-170660  [002] d..21 2056442.480239: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 1448, required space: 8
curl-170660  [002] d..21 2056442.480242: bpf_trace_printk: Stored a TCP option in TCP Flag: 17
curl-170660  [002] D..41 2056442.480251: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
curl-170660  [002] D..41 2056442.480252: bpf_trace_printk: ####=> Socket TCP option data: 42
node-166395  [005] d.s31 2056442.480396: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 1448, required space: 8
node-166395  [005] d.s31 2056442.480416: bpf_trace_printk: Stored a TCP option in TCP Flag: 16
node-166395  [005] D.s51 2056442.480423: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
node-166395  [005] D.s51 2056442.480424: bpf_trace_printk: ####=> Socket TCP option data: 42
```
