# eBPF TPROXY implementation

This repository demos a BPF based iptables TPROXY implementation.

## Building

```
$ cargo build
```

## Demo

In terminal 1, run:

```
$ sudo ./target/debug/proxy --addr 127.0.0.1 --port 9999
```

This is the proxy server. It will received the TPROXY'd packets.

In terminal 2, run:

```
$ sudo ./target/debug/tproxy --ifindex 1 --port 1003 --proxy-addr 127.0.0.1 --proxy-port 9999
```

This is the BPF based TPROXY driver. We are telling `tproxy` to watch ingress on
ifindex 1 (usually `lo`) and proxy TCP packets arriving on port 1003 to the proxy
which is listening with `IP_TRANSPARENT` on `localhost:9999`.

Finally, in terminal 3, run:

```
$ echo asdf | nc -s 127.0.0.5 127.0.0.1 1003
```

This sends a message via TCP to `127.0.0.1:1003`.

In terminal 1 you should now see something like:

```
New connection:
        local: 127.0.0.1:1003
        peer: 127.0.0.5:58783
```
