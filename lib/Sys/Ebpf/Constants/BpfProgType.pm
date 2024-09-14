package Sys::Ebpf::Constants::BpfProgType;

use strict;
use warnings;
use utf8;

use Exporter 'import';

my %constants = (
    'BPF_PROG_TYPE_UNSPEC'                  => 0,
    'BPF_PROG_TYPE_SOCKET_FILTER'           => 1,
    'BPF_PROG_TYPE_KPROBE'                  => 2,
    'BPF_PROG_TYPE_SCHED_CLS'               => 3,
    'BPF_PROG_TYPE_SCHED_ACT'               => 4,
    'BPF_PROG_TYPE_TRACEPOINT'              => 5,
    'BPF_PROG_TYPE_XDP'                     => 6,
    'BPF_PROG_TYPE_PERF_EVENT'              => 7,
    'BPF_PROG_TYPE_CGROUP_SKB'              => 8,
    'BPF_PROG_TYPE_CGROUP_SOCK'             => 9,
    'BPF_PROG_TYPE_LWT_IN'                  => 10,
    'BPF_PROG_TYPE_LWT_OUT'                 => 11,
    'BPF_PROG_TYPE_LWT_XMIT'                => 12,
    'BPF_PROG_TYPE_SOCK_OPS'                => 13,
    'BPF_PROG_TYPE_SK_SKB'                  => 14,
    'BPF_PROG_TYPE_CGROUP_DEVICE'           => 15,
    'BPF_PROG_TYPE_SK_MSG'                  => 16,
    'BPF_PROG_TYPE_RAW_TRACEPOINT'          => 17,
    'BPF_PROG_TYPE_CGROUP_SOCK_ADDR'        => 18,
    'BPF_PROG_TYPE_LWT_SEG6LOCAL'           => 19,
    'BPF_PROG_TYPE_LIRC_MODE2'              => 20,
    'BPF_PROG_TYPE_SK_REUSEPORT'            => 21,
    'BPF_PROG_TYPE_FLOW_DISSECTOR'          => 22,
    'BPF_PROG_TYPE_CGROUP_SYSCTL'           => 23,
    'BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE' => 24,
    'BPF_PROG_TYPE_CGROUP_SOCKOPT'          => 25,
    'BPF_PROG_TYPE_TRACING'                 => 26,
    'BPF_PROG_TYPE_STRUCT_OPS'              => 27,
    'BPF_PROG_TYPE_EXT'                     => 28,
    'BPF_PROG_TYPE_LSM'                     => 29,
    'BPF_PROG_TYPE_SK_LOOKUP'               => 30,
    'BPF_PROG_TYPE_SYSCALL'                 => 31,
    'BPF_PROG_TYPE_NETFILTER'               => 32,
    '__MAX_BPF_PROG_TYPE'                   => 33,
);

our @EXPORT_OK   = keys %constants;
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

for my $name (@EXPORT_OK) {
    no strict 'refs';
    *{$name} = sub () { $constants{$name} };
}

sub get_bpf_prog_type {
    my ($input) = @_;

    my %prefix_to_type = (
        'kprobe/'          => 'BPF_PROG_TYPE_KPROBE',
        'kretprobe/'       => 'BPF_PROG_TYPE_KPROBE',
        'tracepoint/'      => 'BPF_PROG_TYPE_TRACEPOINT',
        'xdp/'             => 'BPF_PROG_TYPE_XDP',
        'perf_event/'      => 'BPF_PROG_TYPE_PERF_EVENT',
        'socket/'          => 'BPF_PROG_TYPE_SOCKET_FILTER',
        'cgroup/'          => 'BPF_PROG_TYPE_CGROUP_SKB',
        'sched/'           => 'BPF_PROG_TYPE_SCHED_CLS',
        'lwt_in/'          => 'BPF_PROG_TYPE_LWT_IN',
        'lwt_out/'         => 'BPF_PROG_TYPE_LWT_OUT',
        'lwt_xmit/'        => 'BPF_PROG_TYPE_LWT_XMIT',
        'sock_ops/'        => 'BPF_PROG_TYPE_SOCK_OPS',
        'sk_skb/'          => 'BPF_PROG_TYPE_SK_SKB',
        'sk_msg/'          => 'BPF_PROG_TYPE_SK_MSG',
        'raw_tp/'          => 'BPF_PROG_TYPE_RAW_TRACEPOINT',
        'lirc_mode2/'      => 'BPF_PROG_TYPE_LIRC_MODE2',
        'flow_dissector/'  => 'BPF_PROG_TYPE_FLOW_DISSECTOR',
        'cgroup_sysctl/'   => 'BPF_PROG_TYPE_CGROUP_SYSCTL',
        'raw_tp_writable/' => 'BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE',
        'cgroup_sockopt/'  => 'BPF_PROG_TYPE_CGROUP_SOCKOPT',
        'tracing/'         => 'BPF_PROG_TYPE_TRACING',
        'struct_ops/'      => 'BPF_PROG_TYPE_STRUCT_OPS',
        'ext/'             => 'BPF_PROG_TYPE_EXT',
        'lsm/'             => 'BPF_PROG_TYPE_LSM',
        'sk_lookup/'       => 'BPF_PROG_TYPE_SK_LOOKUP',
        'syscall/'         => 'BPF_PROG_TYPE_SYSCALL',
        'netfilter/'       => 'BPF_PROG_TYPE_NETFILTER',
    );

    foreach my $prefix ( keys %prefix_to_type ) {
        if ( $input =~ /^$prefix/ ) {
            my $type = $prefix_to_type{$prefix};
            return ( $type, $constants{$type} );
        }
    }

    return ( 'BPF_PROG_TYPE_UNSPEC', $constants{'BPF_PROG_TYPE_UNSPEC'} );
}

@EXPORT_OK = ( @EXPORT_OK, 'get_bpf_prog_type' );
1;
