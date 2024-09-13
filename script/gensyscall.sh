#!/bin/bash
ORIG_PWD=$(pwd)
echo "Original PWD: $ORIG_PWD"

pushd /usr/include/x86_64-linux-gnu/sys/
echo "Current directory for syscall.h: $(pwd)"

echo "Generate syscall.ph file"
echo "h2ph -d \"$ORIG_PWD/lib/Sys/Ebpf/Syscall\" -a -l syscall.h"

h2ph -d "$ORIG_PWD/lib/Sys/Ebpf/Syscall" -a -l syscall.h

popd
