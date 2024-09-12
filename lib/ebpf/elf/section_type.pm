package ebpf::elf::section_type;

use strict;
use warnings;
use utf8;

use Exporter 'import';

our $VERSION = $ebpf::VERSION;

my @constants = (
    'SHT_NULL',         0,
    'SHT_PROGBITS',     1,
    'SHT_SYMTAB',       2,
    'SHT_STRTAB',       3,
    'SHT_RELA',         4,
    'SHT_HASH',         5,
    'SHT_DYNAMIC',      6,
    'SHT_NOTE',         7,
    'SHT_NOBITS',       8,
    'SHT_REL',          9,
    'SHT_SHLIB',        10,
    'SHT_DYNSYM',       11,
    'SHT_NUM',          12,
    'SHT_LOPROC',       0x70000000,
    'SHT_ARM_EXIDX',    0x70000001,
    'SHT_HIPROC',       0x7fffffff,
    'SHT_LOUSER',       0x80000000,
    'SHT_HIUSER',       0xffffffff,
    'SHF_WRITE',        1,
    'SHF_ALLOC',        2,
    'SHF_EXECINSTR',    4,
    'SHF_MASKPROC',     0xf0000000,
);

our @EXPORT_OK;
while (@constants) {
    my ($name, $value) = (shift @constants, shift @constants);
    no strict 'refs';
    *{$name} = sub { $value };
    push @EXPORT_OK, $name;
}

1;