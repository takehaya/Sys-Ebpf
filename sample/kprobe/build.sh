#!/bin/bash

# This script is used to build the sample program for kprobe.
clang -O2 -emit-llvm -c kprobe.c -o - | llc -march=bpf -filetype=obj -o kprobe.o
# clang -target bpf -g -c kprobe.c