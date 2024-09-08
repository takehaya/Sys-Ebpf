#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <linux/bpf.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

int load_bpf_program(
    int prog_type, 
    const void *insns, 
    size_t insn_cnt, 
    const char *license, 
    char *log_buf, 
    size_t log_buf_sz) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.prog_type = prog_type;
    attr.insns = (unsigned long)insns;
    attr.insn_cnt = insn_cnt;
    attr.license = (unsigned long)license;
    attr.log_buf = (unsigned long)log_buf;
    attr.log_size = log_buf_sz;
    attr.log_level = 1;

    int fd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        perror("BPF program load failed");
    }
    return fd;
}



int load_bpf_map(int map_type, int key_size, int value_size, int max_entries, int map_flags) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    attr.map_flags = map_flags;

    int fd = syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd < 0) {
        perror("BPF map creation failed");
    }
    return fd;
}

MODULE = ebpf::c_bpf_loader    PACKAGE = ebpf::c_bpf_loader

int
load_bpf_program(prog_type, insns, insn_cnt, license, log_buf, log_buf_sz)
    int prog_type
    SV *insns
    size_t insn_cnt
    const char *license
    SV *log_buf
    size_t log_buf_sz
CODE:
{
    char *insns_ptr = SvPV_nolen(insns);
    char *log_buf_ptr = SvPV_nolen(log_buf);
    RETVAL = load_bpf_program(prog_type, insns_ptr, insn_cnt, license, log_buf_ptr, log_buf_sz);
}
OUTPUT:
    RETVAL

int
load_bpf_map(map_type, key_size, value_size, max_entries, map_flags)
    int map_type
    int key_size
    int value_size
    int max_entries
    int map_flags
CODE:
{
    RETVAL = load_bpf_map(map_type, key_size, value_size, max_entries, map_flags);
}
OUTPUT:
    RETVAL
