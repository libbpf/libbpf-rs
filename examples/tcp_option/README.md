# TCP Header Modification Example
This example focuses on modifying TCP headers, demonstrating how users can extend and manipulate network packet headers as required.

## Building

```shell
$ cargo build
```

## Usage

```shell
$ sudo ./target/debug/tcp_option --ip <target> --trace-id <id or something>
```

## Trigger

```shell
# Start
$ sudo ./target/debug/tcp_option --ip 127.0.0.1 --trace-id 42

# Start a listener
$ nc -l 127.0.0.1 65000 &

# Start a connector
$ echo test | nc 127.0.0.1 65000
```

> Note that using 127.0.0.1 may result in a mixed output of modified TCP headers in both directions. In fact, only the response message of the machine where the program is deployed will be modified.

## Output

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```

```text
<...>-190048  [000] d..21 2094364.690447: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 524, required space: 8
<...>-190048  [000] d..21 2094364.690477: bpf_trace_printk: Stored a TCP option in TCP Flag: 2
<...>-190048  [000] D..21 2094364.690500: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<...>-190048  [000] D..21 2094364.690501: bpf_trace_printk: ####=> Socket TCP option data: 42
<...>-190048  [000] d.s31 2094364.690507: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<...>-190048  [000] d.s31 2094364.690508: bpf_trace_printk: ####=> Socket TCP option data: 42
<...>-190048  [000] d..21 2094364.690540: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 32741, required space: 8
<...>-190048  [000] d..21 2094364.690551: bpf_trace_printk: Stored a TCP option in TCP Flag: 16
<...>-190048  [000] D..21 2094364.690556: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<...>-190048  [000] D..21 2094364.690556: bpf_trace_printk: ####=> Socket TCP option data: 42
<...>-190048  [000] d.s31 2094364.690560: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<...>-190048  [000] d.s31 2094364.690562: bpf_trace_printk: ####=> Socket TCP option data: 42
<...>-190048  [000] d..21 2094364.690632: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 32741, required space: 8
<...>-190048  [000] d..21 2094364.690643: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 32741, required space: 13
<...>-190048  [000] d..21 2094364.690646: bpf_trace_printk: Stored a TCP option in TCP Flag: 24
<...>-190048  [000] D..21 2094364.690651: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<...>-190048  [000] D..21 2094364.690654: bpf_trace_printk: ####=> Socket TCP option data: 42
<...>-190048  [000] d.s31 2094364.690657: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<...>-190048  [000] d.s31 2094364.690658: bpf_trace_printk: ####=> Socket TCP option data: 42
<...>-190048  [000] d.s41 2094364.690671: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 32768, required space: 8
<...>-190048  [000] d.s41 2094364.690673: bpf_trace_printk: Stored a TCP option in TCP Flag: 16
<...>-190048  [000] D.s41 2094364.690677: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<...>-190048  [000] D.s41 2094364.690678: bpf_trace_printk: ####=> Socket TCP option data: 42
<...>-190048  [000] d.s31 2094364.690681: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<...>-190048  [000] d.s31 2094364.690682: bpf_trace_printk: ####=> Socket TCP option data: 42
    nc-190048  [000] d..21 2094379.828439: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 32768, required space: 8
    nc-190048  [000] d..21 2094379.828469: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 32768, required space: 8
    nc-190048  [000] d..21 2094379.828472: bpf_trace_printk: Stored a TCP option in TCP Flag: 17
    nc-190048  [000] D..21 2094379.828496: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
    nc-190048  [000] D..21 2094379.828498: bpf_trace_printk: ####=> Socket TCP option data: 42
    nc-190048  [000] d.s31 2094379.828507: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
    nc-190048  [000] d.s31 2094379.828517: bpf_trace_printk: ####=> Socket TCP option data: 42
<...>-190022  [002] d..21 2094379.828606: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 32768, required space: 8
<...>-190022  [002] d..21 2094379.828636: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 32768, required space: 8
<...>-190022  [002] d..21 2094379.828639: bpf_trace_printk: Stored a TCP option in TCP Flag: 17
<...>-190022  [002] D..21 2094379.828652: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<...>-190022  [002] D..21 2094379.828653: bpf_trace_printk: ####=> Socket TCP option data: 42
<...>-190022  [002] d.s31 2094379.828659: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<...>-190022  [002] d.s31 2094379.828661: bpf_trace_printk: ####=> Socket TCP option data: 42
<...>-190022  [002] d.s41 2094379.828677: bpf_trace_printk: Sufficient space available to store a TCP option, total space: 32768, required space: 8
<...>-190022  [002] d.s41 2094379.828690: bpf_trace_printk: Stored a TCP option in TCP Flag: 16
<...>-190022  [002] D.s41 2094379.828696: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<...>-190022  [002] D.s41 2094379.828697: bpf_trace_printk: ####=> Socket TCP option data: 42
<...>-190022  [002] d.s31 2094379.828717: bpf_trace_printk: ####=> Socket TCP option magic: 0xeb9f
<...>-190022  [002] d.s31 2094379.828718: bpf_trace_printk: ####=> Socket TCP option data: 42
```
