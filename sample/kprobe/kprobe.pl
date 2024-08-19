#!/usr/bin/env perl

use strict;
use warnings;
use lib '../../lib';  # lib ディレクトリへの相対パスを追加
use ebpf::reader;

my $file = "kprobe.o";
my $reader = ebpf::reader->new($file);
my $data = $reader->parse_ebpf();
print "magic: $data->{magic}\n";