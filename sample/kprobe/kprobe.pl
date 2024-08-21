#!/usr/bin/env perl

use strict;
use warnings;
use lib '../../lib';  # lib ディレクトリへの相対パスを追加
use ebpf::loader;
use Data::Dumper;

my $file = "kprobe.o";
my $loader = ebpf::loader->new($file);
my $data = $loader->load();
print Dumper($data);

$loader->attach_bpf("kprobe/sys_read", sub {
    my ($ctx) = @_;
    print "kprobe/sys_read: $ctx->{pid}, $ctx->{comm}, $ctx->{ret}\n";
});

# いろいろな出力方法があるっぽい
# print Dumper($data);
# print "magic: $data->{magic}, $data->{class}\n";
# while (my ($key, $value) = each %$data) {
#     print "$key: $value\n";
# }