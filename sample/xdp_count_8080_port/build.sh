#!/bin/bash

clang -O3 -emit-llvm -c xdp_count_8080_port.c -o - | llc -march=bpf -filetype=obj -o xdp_count_8080_port.o
