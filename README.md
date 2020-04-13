WARNING: this repo under heavy development. A minimal
prototype will be ready to use and uploaded to crates.io by
June 2020.

# libbpf-rs

Idiomatic rust wrapper around
[libbpf](https://github.com/libbpf/libbpf)

To use in your project, add into your Cargo.toml:

```
...
[dependencies]
libbpf-rs = "0.1"
```

# libbpf-cargo

Cargo subcommand to build bpf programs

To use:

```
$ cargo install libbpf-cargo
$ cargo libbpf --help
```
