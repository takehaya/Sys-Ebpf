use strict;
use warnings;
use Test::More;

# Load the module you're testing
use lib '../lib';  # Adjust the path based on your module's location
use ebpf::asm;
use ebpf::loader;

use ebpf::constants::bpf_map_type qw(BPF_MAP_TYPE_ARRAY);

my $loader = ebpf::loader->new("");

my %map_attr = (
    map_type => BPF_MAP_TYPE_ARRAY,
    key_size => 4,    # sizeof(__u32)
    value_size => 8,  # sizeof(__u64)
    max_entries => 1, # 最大エントリ数
    map_flags => 0,   # 追加のフラグ
    map_name => "kprobe_map",
);

my $fd = $loader->load_bpf_map(\%map_attr);

ok($fd > 0, "Created map fd is $fd");

done_testing();