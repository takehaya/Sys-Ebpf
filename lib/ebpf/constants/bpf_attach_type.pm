package ebpf::constants::bpf_attach_type;

use strict;
use warnings;
use utf8;

use Exporter 'import';

our $VERSION = $ebpf::VERSION;

# 定数を配列で定義
my @constants = (
    'BPF_CGROUP_INET_INGRESS',            0,
    'BPF_CGROUP_INET_EGRESS',             1,
    'BPF_CGROUP_INET_SOCK_CREATE',        2,
    'BPF_SK_SKB_STREAM_PARSER',           3,
    'BPF_SK_SKB_STREAM_VERDICT',          4,
    'BPF_CGROUP_DEVICE',                  5,
    'BPF_SK_MSG_VERDICT',                 6,
    'BPF_CGROUP_INET4_BIND',              7,
    'BPF_CGROUP_INET6_BIND',              8,
    'BPF_CGROUP_INET4_CONNECT',           9,
    'BPF_CGROUP_INET6_CONNECT',           10,
    'BPF_CGROUP_INET4_POST_BIND',         11,
    'BPF_CGROUP_INET6_POST_BIND',         12,
    'BPF_CGROUP_UDP4_SENDMSG',            13,
    'BPF_CGROUP_UDP6_SENDMSG',            14,
    'BPF_LIRC_MODE2',                     15,
    'BPF_FLOW_DISSECTOR',                 16,
    'BPF_CGROUP_SYSCTL',                  17,
    'BPF_CGROUP_UDP4_RECVMSG',            18,
    'BPF_CGROUP_UDP6_RECVMSG',            19,
    'BPF_CGROUP_GETSOCKOPT',              20,
    'BPF_CGROUP_SETSOCKOPT',              21,
    'BPF_TRACE_RAW_TP',                   22,
    'BPF_TRACE_FENTRY',                   23,
    'BPF_TRACE_FEXIT',                    24,
    'BPF_MODIFY_RETURN',                  25,
    'BPF_LSM_MAC',                        26,
    'BPF_TRACE_ITER',                     27,
    'BPF_CGROUP_INET4_GETPEERNAME',       28,
    'BPF_CGROUP_INET6_GETPEERNAME',       29,
    'BPF_CGROUP_INET4_GETSOCKNAME',       30,
    'BPF_CGROUP_INET6_GETSOCKNAME',       31,
    'BPF_XDP_DEVMAP',                     32,
    'BPF_CGROUP_INET_SOCK_RELEASE',       33,
    'BPF_XDP_CPUMAP',                     34,
    'BPF_SK_LOOKUP',                      35,
    'BPF_XDP',                            36,
    'BPF_SK_SKB_VERDICT',                 37,
    'BPF_SK_REUSEPORT_SELECT',            38,
    'BPF_SK_REUSEPORT_SELECT_OR_MIGRATE', 39,
    'BPF_PERF_EVENT',                     40,
    'BPF_TRACE_KPROBE_MULTI',             41,
    'BPF_LSM_CGROUP',                     42,
    'BPF_STRUCT_OPS',                     43,
    'BPF_NETFILTER',                      44,
    'BPF_TCX_INGRESS',                    45,
    'BPF_TCX_EGRESS',                     46,
    'BPF_TRACE_UPROBE_MULTI',             47,
    'BPF_CGROUP_UNIX_CONNECT',            48,
    'BPF_CGROUP_UNIX_SENDMSG',            49,
    'BPF_CGROUP_UNIX_RECVMSG',            50,
    'BPF_CGROUP_UNIX_GETPEERNAME',        51,
    'BPF_CGROUP_UNIX_GETSOCKNAME',        52,
    'BPF_NETKIT_PRIMARY',                 53,
    'BPF_NETKIT_PEER',                    54,
    'BPF_TRACE_KPROBE_SESSION',           55,
    '__MAX_BPF_ATTACH_TYPE',              56,
);

# 定数を定義し、エクスポート用配列に追加
our @EXPORT_OK   = keys %constants;
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

for my $name (@EXPORT_OK) {
    no strict 'refs';
    *{$name} = sub () { $constants{$name} };
}

1;
