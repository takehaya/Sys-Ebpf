#!/usr/bin/env perl

use strict;
use warnings;
use lib '../../lib';  # lib ディレクトリへの相対パスを追加
use lib '../../blib/arch/auto/ebpf/c_bpf_loader';
use ebpf::loader;
use Data::Dumper;

use ebpf::constants::bpf_map_type qw(BPF_MAP_TYPE_ARRAY);

my $file = "kprobe.o";
my $loader = ebpf::loader->new($file);
my $data = $loader->load_elf();
# print Dumper($data);

my %map_attr = (
    "kprobe_map"=>{
        "map_type"=>BPF_MAP_TYPE_ARRAY,
        "key_size"=>4,    # sizeof(__u32)
        "value_size"=>8,  # sizeof(__u64)
        "max_entries"=>1, # 最大エントリ数
        "map_flags"=>0    # 追加のフラグ
    }
);
$loader -> load_bpf("kprobe/sys_execve", \%map_attr);

# いろいろな出力方法があるっぽい
# print Dumper($data);
# print "magic: $data->{magic}, $data->{class}\n";
# while (my ($key, $value) = each %$data) {
#     print "$key: $value\n";
# }