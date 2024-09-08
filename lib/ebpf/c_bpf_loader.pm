package ebpf::c_bpf_loader;

use strict;
use warnings;

our $VERSION = '0.01';

require Exporter;
require DynaLoader;

our @ISA = qw(Exporter DynaLoader);

bootstrap ebpf::c_bpf_loader;

# Perlサブとしてのエクスポート
our @EXPORT_OK = qw(load_bpf_program load_bpf_map);

1;
