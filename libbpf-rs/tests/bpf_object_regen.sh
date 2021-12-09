#!/bin/bash

SRC=$(find bin/src/ -name "*.bpf.c")
BPFTOOL=""

function usage() {
    echo "Usage: ./bpf_object_regen.sh [OPTIONS]"
    echo "    -b: use bpftool to generate bin/src/vmlinux.h"
    echo "        default vmlinux.h from ../../examples/vmlinux_515.h"
    echo "    -o [SCRIPT_NAME]: only compile one object defined by SCRIPT_NAME"
    echo "example: ./bpf_object_regen.sh -b -o bin/src/runqslower.bpf.c"
    exit
}

while [[ ! -z $1 ]]; do
    case "$1" in
        -b|--bpftool)
            BPFTOOL=$(which bpftool)
            if [[ -z $BPFTOOL ]]; then
                echo "No available bpftool: Please consult README.md or your distro's documentation"
                usage
            fi
            ;;
        -o|--only)
            SRC=$2
            if [[ -z $SRC ]]; then
                echo -e "No source files provided"
                usage
            fi
            shift
            ;;
        -h|--help)
            echo "bpf_object_regen.sh: Regenerate libbpf-rs/test bpf objects"
            usage
            ;;
    esac
    shift
done

function compile() {
    base=$(basename -- $file)
    objname="${base%.*}"
    objname+=".o"
    clang -g -O2 -target bpf -c $1 -o bin/$objname
}

if [[ ! -z $BPFTOOL ]]; then
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > bin/src/vmlinux.h
else
    cp ../../examples/vmlinux_515.h bin/src/vmlinux.h
fi

for file in $SRC
do
    compile $file
done

rm bin/src/vmlinux.h
