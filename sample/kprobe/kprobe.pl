#!/usr/bin/env perl

use strict;
use warnings;
use utf8;
use lib '../../lib';    # lib ディレクトリへの相対パスを追加
use Sys::Ebpf::Loader;
use Sys::Ebpf::Link::Perf::Kprobe;
use Data::Dumper qw( Dumper );

my $file   = "kprobe.o";
my $loader = Sys::Ebpf::Loader->new($file);
my $data   = $loader->load_elf();

my $kprobe_fn = "kprobe/sys_execve";

my ( $map_data, $prog_fd ) = $loader->load_bpf($kprobe_fn);
print "prog_fd: $prog_fd\n";
print Dumper($map_data);
my $map_kprobe_map = $map_data->{kprobe_map};
$map_kprobe_map->{key_schema}   = [ [ 'kprobe_map_key',   'uint32' ], ];
$map_kprobe_map->{value_schema} = [ [ 'kprobe_map_value', 'uint64' ], ];

# Kprobeをアタッチ
my $kprobe_info
    = Sys::Ebpf::Link::Perf::Kprobe::attach_kprobe( $prog_fd, $kprobe_fn );

print "Waiting for events..\n";

# 1秒ごとにマップの値を読み取り、表示
while (1) {
    my $key   = { kprobe_map_key => 0 };
    my $value = $map_kprobe_map->lookup($key);
    if ( defined $value ) {
        print Dumper($value);
        printf "%s called %d times\n", $kprobe_fn, $value->{kprobe_map_value};
    }
    else {
        warn "Failed to read map value\n";
    }
    sleep(1);
}

# # クリーンアップ（この部分は実際には実行されませんが、適切な終了処理のために必要です）
END {
    if ($kprobe_info) {
        Sys::Ebpf::Link::Perf::Kprobe::detach_kprobe($kprobe_info);
    }
}
