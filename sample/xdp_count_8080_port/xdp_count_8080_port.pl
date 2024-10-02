#!/usr/bin/env perl

use strict;
use warnings;
use utf8;
use open ":std", ":encoding(UTF-8)";
use lib '../../lib';
use Sys::Ebpf::Loader;
use Sys::Ebpf::Link::Netlink::Xdp;

my $file   = "xdp_count_8080_port.o";
my $loader = Sys::Ebpf::Loader->new($file);
my $data   = $loader->load_elf();

my $xdp_fn = "xdp/xdp_count_8080_port";

my ( $map_data, $prog_fd ) = $loader->load_bpf($xdp_fn);
my $map_xdp_map = $map_data->{xdp_map};
$map_xdp_map->{key_schema}   = [ [ 'xdp_map_key',   'uint32' ] ];
$map_xdp_map->{value_schema} = [ [ 'xdp_map_value', 'uint64' ] ];

# インターフェース名を指定
my $ifname = "ens3";
Sys::Ebpf::Link::Netlink::Xdp::detach_xdp($ifname);
my $xdp_info = Sys::Ebpf::Link::Netlink::Xdp::attach_xdp( $prog_fd, $ifname );

print "Map FD: " . $map_xdp_map->{map_fd} . "\n";
print "Program FD: $prog_fd\n";
print $xdp_info->{ifname} . " にXDPプログラムをアタッチしました。\n";
print "XDPプログラムをアタッチしました。Ctrl+Cで停止します。\n";

while (1) {
    my $key   = { xdp_map_key => 0 };
    my $value = $map_xdp_map->lookup($key);
    if ( defined $value ) {
        printf "パケット数: %d\n", $value->{xdp_map_value};
    }
    sleep(1);
}

END {
    if ($xdp_info) {
        Sys::Ebpf::Link::Netlink::Xdp::detach_xdp($xdp_info);
    }
}
