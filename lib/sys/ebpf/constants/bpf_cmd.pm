package sys::ebpf::constants::bpf_cmd;

use strict;
use warnings;
use utf8;

use Exporter 'import';

our $VERSION = $sys::ebpf::VERSION;

my %constants = (
    'BPF_MAP_CREATE',                  0,
    'BPF_MAP_LOOKUP_ELEM',             1,
    'BPF_MAP_UPDATE_ELEM',             2,
    'BPF_MAP_DELETE_ELEM',             3,
    'BPF_MAP_GET_NEXT_KEY',            4,
    'BPF_PROG_LOAD',                   5,
    'BPF_OBJ_PIN',                     6,
    'BPF_OBJ_GET',                     7,
    'BPF_PROG_ATTACH',                 8,
    'BPF_PROG_DETACH',                 9,
    'BPF_PROG_TEST_RUN',               10,
    'BPF_PROG_RUN',                    10,
    'BPF_PROG_GET_NEXT_ID',            11,
    'BPF_MAP_GET_NEXT_ID',             12,
    'BPF_PROG_GET_FD_BY_ID',           13,
    'BPF_MAP_GET_FD_BY_ID',            14,
    'BPF_OBJ_GET_INFO_BY_FD',          15,
    'BPF_PROG_QUERY',                  16,
    'BPF_RAW_TRACEPOINT_OPEN',         17,
    'BPF_BTF_LOAD',                    18,
    'BPF_BTF_GET_FD_BY_ID',            19,
    'BPF_TASK_FD_QUERY',               20,
    'BPF_MAP_LOOKUP_AND_DELETE_ELEM',  21,
    'BPF_MAP_FREEZE',                  22,
    'BPF_BTF_GET_NEXT_ID',             23,
    'BPF_MAP_LOOKUP_BATCH',            24,
    'BPF_MAP_LOOKUP_AND_DELETE_BATCH', 25,
    'BPF_MAP_UPDATE_BATCH',            26,
    'BPF_MAP_DELETE_BATCH',            27,
    'BPF_LINK_CREATE',                 28,
    'BPF_LINK_UPDATE',                 29,
    'BPF_LINK_GET_FD_BY_ID',           30,
    'BPF_LINK_GET_NEXT_ID',            31,
    'BPF_ENABLE_STATS',                32,
    'BPF_ITER_CREATE',                 33,
    'BPF_LINK_DETACH',                 34,
    'BPF_PROG_BIND_MAP',               35,
    'BPF_TOKEN_CREATE',                36,
    '__MAX_BPF_CMD',                   37,
);

our @EXPORT_OK   = keys %constants;
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

for my $name (@EXPORT_OK) {
    no strict 'refs';
    *{$name} = sub () { $constants{$name} };
}
1;
