#!/bin/bash

PWD=$(pwd)
pushd /usr/include/x86_64-linux-gnu/sys/
h2ph -d "$PWD/lib/Ebpf/Syscall" -a -l syscall.h
popd