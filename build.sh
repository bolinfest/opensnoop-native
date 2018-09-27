#!/bin/sh
# Note the generated opensnoop executable must be run with sudo.
set -e
python opensnoop.py
clang opensnoop.c -O3 -o opensnoop /usr/lib/x86_64-linux-gnu/libbpf.so
