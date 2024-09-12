package ebpf::elf::symbol_type;

use strict;
use warnings;
use utf8;

use Exporter 'import';

our $VERSION = $ebpf::VERSION;

# Symbol Types (lower 4 bits of st_info)
my @constants = (
    'STT_NOTYPE',  0,
    'STT_OBJECT',  1,
    'STT_FUNC',    2,
    'STT_SECTION', 3,
    'STT_FILE',    4,
    'STT_COMMON',  5,
    'STT_TLS',     6,
    'STT_NUM',     7,
    'STT_LOOS',    10,
    'STT_HIOS',    12,
    'STT_LOPROC',  13,
    'STT_HIPROC',  15,
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
sub ST_TYPE {
    my ($info) = @_;
    return $info & 0xf;
}

push @EXPORT_OK, qw(ST_TYPE);

1;