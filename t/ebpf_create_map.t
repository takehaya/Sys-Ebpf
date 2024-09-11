use strict;
use warnings;
use Test::More;

# Load the module you're testing
use lib '../lib';  # Adjust the path based on your module's location
use ebpf::asm;
use ebpf::map;

use ebpf::constants::bpf_map_type qw(BPF_MAP_TYPE_ARRAY);

plan skip_all => "This test must be run as root" if $> != 0;

my %map_attr = (
    map_type => BPF_MAP_TYPE_ARRAY,
    key_size => 4,    # sizeof(__u32)
    value_size => 8,  # sizeof(__u64)
    max_entries => 1, # 最大エントリ数
    map_flags => 0,   # 追加のフラグ
    map_name => "kprobe_map",
);
my $pin_path = "/sys/fs/bpf/kprobe_map";

ebpf::map::unpin_bpf_map($pin_path);

my $map_instance = ebpf::map->create(\%map_attr);
my $fd = $map_instance->{fd};
ok($fd > 0, "Created map fd is $fd");

my $res = ebpf::map::pin_bpf_map($fd, $pin_path);
is($res, 0, "Pinned map to $pin_path: $res");

$res = ebpf::map::unpin_bpf_map($pin_path);
is($res, 0, "Unpinned map from $pin_path: $res");

done_testing();
