#!/bin/bash

# This script is used to build the sample program for kprobe.
clang -O3 -g -emit-llvm -c kprobe.c -o - | llc -march=bpf -filetype=obj -o kprobe.o
