#!/bin/bash

clang -O3 -emit-llvm -c xdp_dport_counter.c -o - | llc -march=bpf -filetype=obj -o xdp_dport_counter.o
