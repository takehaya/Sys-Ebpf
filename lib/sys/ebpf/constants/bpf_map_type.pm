package sys::ebpf::constants::bpf_map_type;

use strict;
use warnings;
use utf8;

use Exporter 'import';

our $VERSION = $sys::ebpf::VERSION;

my %constants = (
    'BPF_MAP_TYPE_UNSPEC',                           0,
    'BPF_MAP_TYPE_HASH',                             1,
    'BPF_MAP_TYPE_ARRAY',                            2,
    'BPF_MAP_TYPE_PROG_ARRAY',                       3,
    'BPF_MAP_TYPE_PERF_EVENT_ARRAY',                 4,
    'BPF_MAP_TYPE_PERCPU_HASH',                      5,
    'BPF_MAP_TYPE_PERCPU_ARRAY',                     6,
    'BPF_MAP_TYPE_STACK_TRACE',                      7,
    'BPF_MAP_TYPE_CGROUP_ARRAY',                     8,
    'BPF_MAP_TYPE_LRU_HASH',                         9,
    'BPF_MAP_TYPE_LRU_PERCPU_HASH',                  10,
    'BPF_MAP_TYPE_LPM_TRIE',                         11,
    'BPF_MAP_TYPE_ARRAY_OF_MAPS',                    12,
    'BPF_MAP_TYPE_HASH_OF_MAPS',                     13,
    'BPF_MAP_TYPE_DEVMAP',                           14,
    'BPF_MAP_TYPE_SOCKMAP',                          15,
    'BPF_MAP_TYPE_CPUMAP',                           16,
    'BPF_MAP_TYPE_XSKMAP',                           17,
    'BPF_MAP_TYPE_SOCKHASH',                         18,
    'BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED',        19,
    'BPF_MAP_TYPE_CGROUP_STORAGE',                   19,
    'BPF_MAP_TYPE_REUSEPORT_SOCKARRAY',              20,
    'BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED', 21,
    'BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE',            21,
    'BPF_MAP_TYPE_QUEUE',                            22,
    'BPF_MAP_TYPE_STACK',                            23,
    'BPF_MAP_TYPE_SK_STORAGE',                       24,
    'BPF_MAP_TYPE_DEVMAP_HASH',                      25,
    'BPF_MAP_TYPE_STRUCT_OPS',                       26,
    'BPF_MAP_TYPE_RINGBUF',                          27,
    'BPF_MAP_TYPE_INODE_STORAGE',                    28,
    'BPF_MAP_TYPE_TASK_STORAGE',                     29,
    'BPF_MAP_TYPE_BLOOM_FILTER',                     30,
    'BPF_MAP_TYPE_USER_RINGBUF',                     31,
    'BPF_MAP_TYPE_CGRP_STORAGE',                     32,
    'BPF_MAP_TYPE_ARENA',                            33,
    '__MAX_BPF_MAP_TYPE',                            34,
);

our @EXPORT_OK   = keys %constants;
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

for my $name (@EXPORT_OK) {
    no strict 'refs';
    *{$name} = sub () { $constants{$name} };
}

1;
