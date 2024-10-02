#!/usr/bin/env perl

use strict;
use warnings;
use utf8;
use lib '../../lib';
use Sys::Ebpf::Loader;
use Sys::Ebpf::Link::Perf::Kprobe;

my $file   = "kprobe_file_open_tracker.o";
my $loader = Sys::Ebpf::Loader->new($file);
my $data   = $loader->load_elf();

my $kprobe_fn = "kprobe/sys_open";

my ( $map_data, $prog_fd ) = $loader->load_bpf($kprobe_fn);
my $map_file_open = $map_data->{file_open_map};
$map_file_open->{key_schema} = [ [ 'pid', 'uint32' ] ];
$map_file_open->{value_schema}
    = [ [ 'count', 'uint32' ], [ 'filename', 'string[128]' ] ];

my $kprobe_info
    = Sys::Ebpf::Link::Perf::Kprobe::attach_kprobe( $prog_fd, $kprobe_fn );

print "Program FD: $prog_fd\n";
print "ファイルオープンの追跡を開始します。Ctrl+Cで停止します。\n";

$map_file_open->update( { pid => $$ }, { count => 0, filename => "sample" } );

while (1) {
    my $prev_key    = undef;
    my $has_entries = 0;
    while ( defined( my $key = $map_file_open->get_next_key($prev_key) ) ) {
        $has_entries = 1;
        my $value = $map_file_open->lookup($key);
        if ( defined $value ) {
            printf "PID: %d, ファイル名: %s, オープン回数: %d\n",
                $key->{pid}, $value->{filename}, $value->{count};
        }
        $prev_key = $key;
        sleep(1);
    }
    if ( !$has_entries ) {
        print "マップにエントリがありません。\n";
    }
    print "---\n";
    sleep(1);
}

END {
    if ($kprobe_info) {
        Sys::Ebpf::Link::Perf::Kprobe::detach_kprobe($kprobe_info);
    }
}
