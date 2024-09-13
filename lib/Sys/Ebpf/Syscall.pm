package Sys::Ebpf::Syscall;

use strict;
use warnings;
use utf8;
use Exporter 'import';

require 'Sys/Ebpf/Syscall/sys/syscall.ph';

our @EXPORT = grep {/^SYS_/} keys %main::;

1;
