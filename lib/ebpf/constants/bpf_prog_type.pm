package ebpf::constants::bpf_prog_type;

use strict;
use warnings;
use Exporter 'import';

our $VERSION = $ebpf::VERSION;

my @constants = (
    'BPF_PROG_TYPE_UNSPEC',              0,
    'BPF_PROG_TYPE_SOCKET_FILTER',       1,
    'BPF_PROG_TYPE_KPROBE',              2,
    'BPF_PROG_TYPE_SCHED_CLS',           3,
    'BPF_PROG_TYPE_SCHED_ACT',           4,
    'BPF_PROG_TYPE_TRACEPOINT',          5,
    'BPF_PROG_TYPE_XDP',                 6,
    'BPF_PROG_TYPE_PERF_EVENT',          7,
    'BPF_PROG_TYPE_CGROUP_SKB',          8,
    'BPF_PROG_TYPE_CGROUP_SOCK',         9,
    'BPF_PROG_TYPE_LWT_IN',              10,
    'BPF_PROG_TYPE_LWT_OUT',             11,
    'BPF_PROG_TYPE_LWT_XMIT',            12,
    'BPF_PROG_TYPE_SOCK_OPS',            13,
    'BPF_PROG_TYPE_SK_SKB',              14,
    'BPF_PROG_TYPE_CGROUP_DEVICE',       15,
    'BPF_PROG_TYPE_SK_MSG',              16,
    'BPF_PROG_TYPE_RAW_TRACEPOINT',      17,
    'BPF_PROG_TYPE_CGROUP_SOCK_ADDR',    18,
    'BPF_PROG_TYPE_LWT_SEG6LOCAL',       19,
    'BPF_PROG_TYPE_LIRC_MODE2',          20,
    'BPF_PROG_TYPE_SK_REUSEPORT',        21,
    'BPF_PROG_TYPE_FLOW_DISSECTOR',      22,
    'BPF_PROG_TYPE_CGROUP_SYSCTL',       23,
    'BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE', 24,
    'BPF_PROG_TYPE_CGROUP_SOCKOPT',      25,
    'BPF_PROG_TYPE_TRACING',             26,
    'BPF_PROG_TYPE_STRUCT_OPS',          27,
    'BPF_PROG_TYPE_EXT',                 28,
    'BPF_PROG_TYPE_LSM',                 29,
    'BPF_PROG_TYPE_SK_LOOKUP',           30,
    'BPF_PROG_TYPE_SYSCALL',             31,
    'BPF_PROG_TYPE_NETFILTER',           32,
    '__MAX_BPF_PROG_TYPE',               33,
);

our @EXPORT_OK;
while (@constants) {
    my ($name, $value) = (shift @constants, shift @constants);
    no strict 'refs';
    *{$name} = sub { $value };
    push @EXPORT_OK, $name;
}

1;
