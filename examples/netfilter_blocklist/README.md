# eBPF Netfilter Blocklist Example

This project demonstrates how to use eBPF and Rust to implement a Netfilter hook that blocks specific IPv4 traffic based on a blacklist of IP addresses. The eBPF program uses an LPM Trie map to efficiently store and lookup IP addresses, and the Rust program handles the loading, configuration, and management of the eBPF program.


## ⚠ Requirements ⚠

Linux kernel [version 6.4 or later](https://github.com/torvalds/linux/commit/84601d6ee68ae820dec97450934797046d62db4b) with eBPF support.

```shell
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./examples/netfilter_blocklist/src/bpf/vmlinux.h
```

## Building

```shell
$ cargo build
```

## Usage

```shell
$ sudo ./target/release/netfilter_blocklist --block-ip <target ip> --value <show in debug> --verbose
```

## Trigger

```shell
# Start
$ sudo ./target/release/netfilter_blocklist --block-ip 1.1.1.1 --value 42 --verbose

# Trigger using curl
curl 1.1.1.1
```

## Output

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```
```text
            curl-106738  [001] ...1. 74215.769718: bpf_trace_printk: Blocked IP: 1.1.1.1, prefix length: 32, map value: 42

          <idle>-0       [001] ..s3. 74216.785447: bpf_trace_printk: Blocked IP: 1.1.1.1, prefix length: 32, map value: 42

          <idle>-0       [001] ..s3. 74217.801426: bpf_trace_printk: Blocked IP: 1.1.1.1, prefix length: 32, map value: 42

          <idle>-0       [002] ..s3. 74218.825369: bpf_trace_printk: Blocked IP: 1.1.1.1, prefix length: 32, map value: 42

          <idle>-0       [000] ..s3. 74219.849344: bpf_trace_printk: Blocked IP: 1.1.1.1, prefix length: 32, map value: 42

          <idle>-0       [000] ..s3. 74220.873297: bpf_trace_printk: Blocked IP: 1.1.1.1, prefix length: 32, map value: 42

          <idle>-0       [003] ..s3. 74222.889199: bpf_trace_printk: Blocked IP: 1.1.1.1, prefix length: 32, map value: 42

          <idle>-0       [001] ..s3. 74227.145032: bpf_trace_printk: Blocked IP: 1.1.1.1, prefix length: 32, map value: 42
```
