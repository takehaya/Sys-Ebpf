#!/usr/bin/env perl

use strict;
use warnings;
use utf8;
use lib '../../lib';
use Sys::Ebpf::Loader;
use Sys::Ebpf::Link::Perf::Kprobe;

my $file   = "kprobe_file_open_counter.o";
my $loader = Sys::Ebpf::Loader->new($file);
my $data   = $loader->load_elf();

my $kprobe_fn = "kprobe/sys_open";

my ( $map_data, $prog_fd ) = $loader->load_bpf($kprobe_fn);
my $map_kprobe_map = $map_data->{kprobe_map};
$map_kprobe_map->{key_schema}   = [ [ 'kprobe_map_key',   'uint32' ] ];
$map_kprobe_map->{value_schema} = [ [ 'kprobe_map_value', 'uint64' ] ];

my $kprobe_info
    = Sys::Ebpf::Link::Perf::Kprobe::attach_kprobe( $prog_fd, $kprobe_fn );

print "Map FD: " . $map_kprobe_map->{map_fd} . "\n";
print "Program FD: $prog_fd\n";
sleep(1);
print "Counting file opens. Press Ctrl+C to stop.\n";

while (1) {
    my $key   = { kprobe_map_key => 1 };
    my $value = $map_kprobe_map->lookup($key);
    if ( defined $value ) {
        printf "Files opened: %d\n", $value->{kprobe_map_value};
    }
    sleep(1);
}

END {
    if ($kprobe_info) {
        Sys::Ebpf::Link::Perf::Kprobe::detach_kprobe($kprobe_info);
    }
}
