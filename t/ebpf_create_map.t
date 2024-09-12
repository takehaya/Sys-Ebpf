use strict;
use warnings;
use Test::More;

# Load the module you're testing
use lib '../lib';
use ebpf::asm;
use ebpf::map;

use ebpf::constants::bpf_map_type qw(BPF_MAP_TYPE_HASH);
use ebpf::constants::bpf_map_create_flags qw(BPF_F_NO_PREALLOC BPF_F_NUMA_NODE combine_flags);

plan skip_all => "This test must be run as root" if $> != 0;

my %map_attr = (
    map_type => BPF_MAP_TYPE_HASH,
    key_size => 4,    # sizeof(__u32)
    value_size => 8,  # sizeof(__u64)
    max_entries => 1024,
    map_name => "kprobe_map",
    map_flags => combine_flags(BPF_F_NO_PREALLOC, BPF_F_NUMA_NODE),
);
my $pin_path = "/sys/fs/bpf/kprobe_map";

ebpf::map::unpin_bpf_map($pin_path);

my $map_instance = ebpf::map->create(\%map_attr);
my $map_fd = $map_instance->{map_fd};
ok($map_fd > 0, "Created map fd is $map_fd");

ok(
    $map_instance->{map_flags} == combine_flags(BPF_F_NO_PREALLOC, BPF_F_NUMA_NODE),
    "Map flags are correct",
);

my $res = ebpf::map::pin_bpf_map($map_fd, $pin_path);
is($res, 0, "Pinned map to $pin_path: $res");

$res = ebpf::map::unpin_bpf_map($pin_path);
is($res, 0, "Unpinned map from $pin_path: $res");


END {
   if ($map_instance) {
       $map_instance->close();
       undef $map_instance;
       sleep 0.5;
   }
}
done_testing();
