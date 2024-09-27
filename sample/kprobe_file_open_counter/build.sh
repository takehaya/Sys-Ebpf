#!/bin/bash

clang -O3 -emit-llvm -c kprobe_file_open_counter.c -o - | llc -march=bpf -filetype=obj -o kprobe_file_open_counter.o
