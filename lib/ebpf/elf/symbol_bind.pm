package ebpf::elf::symbol_bind;

use strict;
use warnings;
use utf8;

use Exporter 'import';

our $VERSION = $ebpf::VERSION;

# Symbol Bindings (upper 4 bits of st_info)
my @constants = (
    'STB_LOCAL',   0,
    'STB_GLOBAL',  1,
    'STB_WEAK',    2,
    'STB_NUM',     3,
    'STB_LOOS',    10,
    'STB_HIOS',    12,
    'STB_LOPROC',  13,
    'STB_HIPROC',  15,
);

our @EXPORT_OK;

# Symbol Types
while (@constants) {
    my ($name, $value) = (shift @constants, shift @constants);
    no strict 'refs';
    *{$name} = sub { $value };
    push @EXPORT_OK, $name;
}

# Helper functions
sub ST_BIND {
    my ($info) = @_;
    return $info >> 4;
}

push @EXPORT_OK, qw(ST_BIND);

1;