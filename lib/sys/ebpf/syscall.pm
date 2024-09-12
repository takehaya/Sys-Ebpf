package sys::ebpf::syscall;

use strict;
use warnings;
use utf8;
use Exporter 'import';

require 'sys/ebpf/syscall/sys/syscall.ph';

our @EXPORT = grep {/^SYS_/} keys %main::;

1;
