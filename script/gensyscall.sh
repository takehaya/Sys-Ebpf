#!/bin/bash
ORIG_PWD=$(pwd)
echo "Original PWD: $ORIG_PWD"


pushd /usr/include/linux/
h2ph -d "$ORIG_PWD/lib/Sys/Ebpf/Link/Perf/Dump" -a -l perf_event.h
popd

pushd /usr/include/x86_64-linux-gnu/sys/
echo "Generate headers file"

h2ph -d "$ORIG_PWD/lib/Sys/Ebpf/Syscall" -a -l syscall.h
h2ph -d "$ORIG_PWD/lib/Sys/Ebpf/Elf/Constants" -a -l elf.h

# h2ph -d "$ORIG_PWD/lib/Sys/Ebpf/Ioctl" -a -l ioctl.h


popd
