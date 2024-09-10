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


$loader -> load_bpf("kprobe/sys_execve");

# いろいろな出力方法があるっぽい
# print Dumper($data);
# print "magic: $data->{magic}, $data->{class}\n";
# while (my ($key, $value) = each %$data) {
#     print "$key: $value\n";
# }