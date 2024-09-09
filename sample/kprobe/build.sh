#!/bin/bash

# This script is used to build the sample program for kprobe.
clang -O3 -emit-llvm -c kprobe.c -o - | llc -march=bpf -filetype=obj -o kprobe.o
# clang -target bpf -g -c kprobe.c
# clang -O3 -target bpf -c kprobe.c -o kprobe.o
