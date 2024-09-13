package Sys::Ebpf::Elf::SectionFlagType;

use strict;
use warnings;
use utf8;

use Exporter 'import';

our $VERSION = $Sys::Ebpf::VERSION;

my @constants = (
    'SHF_WRITE',      1 << 0,     'SHF_ALLOC',            1 << 1,
    'SHF_EXECINSTR',  1 << 2,     'SHF_MERGE',            1 << 4,
    'SHF_STRINGS',    1 << 5,     'SHF_INFO_LINK',        1 << 6,
    'SHF_LINK_ORDER', 1 << 7,     'SHF_OS_NONCONFORMING', 1 << 8,
    'SHF_GROUP',      1 << 9,     'SHF_TLS',              1 << 10,
    'SHF_COMPRESSED', 1 << 11,    'SHF_MASKOS',           0x0ff00000,
    'SHF_MASKPROC',   0xf0000000, 'SHF_ORDERED',          1 << 30,
    'SHF_EXCLUDE',    1 << 31,
);

our @EXPORT_OK;
while (@constants) {
    my ( $name, $value ) = ( shift @constants, shift @constants );
    no strict 'refs';
    *{$name} = sub {$value};
    push @EXPORT_OK, $name;
}

1;
