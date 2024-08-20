#!/usr/bin/env perl

use strict;
use warnings;
use lib '../../lib';  # lib ディレクトリへの相対パスを追加
use ebpf::reader;
use Data::Dumper;

my $file = "kprobe.o";
my $reader = ebpf::reader->new($file);
my $data = $reader->parse_ebpf();

# いろいろな出力方法があるっぽい
print Dumper($data);
# print "magic: $data->{magic}, $data->{class}\n";
# while (my ($key, $value) = each %$data) {
#     print "$key: $value\n";
# }