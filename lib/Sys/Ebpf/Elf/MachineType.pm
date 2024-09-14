package Sys::Ebpf::Elf::MachineType;

use strict;
use warnings;
use utf8;

sub get_machine_name {
    my ( $self, $e_machine ) = @_;

    my %machine_names = (
        EM_NONE         => 'No machine',
        EM_M32          => 'AT&T WE 32100',
        EM_SPARC        => 'SPARC',
        EM_386          => 'Intel 80386',
        EM_68K          => 'Motorola 68000',
        EM_88K          => 'Motorola 88000',
        EM_486          => 'Intel 80486',
        EM_860          => 'Intel 80860',
        EM_MIPS         => 'MIPS I Architecture',
        EM_MIPS_RS3_LE  => 'MIPS RS3000 Little-endian',
        EM_PARISC       => 'HP/PA',
        EM_SPARC32PLUS  => 'SPARC with enhanced instruction set',
        EM_PPC          => 'PowerPC',
        EM_PPC64        => 'PowerPC 64-bit',
        EM_SPU          => 'Sony/Toshiba/IBM SPU',
        EM_ARM          => 'ARM',
        EM_SH           => 'Renesas SuperH',
        EM_SPARCV9      => 'SPARC Version 9',
        EM_H8_300       => 'Renesas H8/300',
        EM_IA_64        => 'Intel Itanium',
        EM_X86_64       => 'AMD x86-64',
        EM_S390         => 'IBM S/390',
        EM_CRIS         => 'Axis Communications 32-bit embedded processor',
        EM_M32R         => 'Renesas M32R',
        EM_MN10300      => 'Panasonic/MEI MN10300, AM33',
        EM_OPENRISC     => 'OpenRISC 32-bit embedded processor',
        EM_ARCOMPACT    => 'ARCompact processor',
        EM_XTENSA       => 'Tensilica Xtensa Architecture',
        EM_BLACKFIN     => 'ADI Blackfin Processor',
        EM_UNICORE      => 'UniCore-32',
        EM_ALTERA_NIOS2 => 'Altera Nios II soft-core processor',
        EM_TI_C6000     => 'TI C6X DSPs',
        EM_HEXAGON      => 'QUALCOMM Hexagon',
        EM_NDS32        =>
            'Andes Technology compact code size embedded RISC processor family',
        EM_AARCH64        => 'ARM 64-bit',
        EM_TILEPRO        => 'Tilera TILEPro',
        EM_MICROBLAZE     => 'Xilinx MicroBlaze',
        EM_TILEGX         => 'Tilera TILE-Gx',
        EM_ARCV2          => 'ARCv2 Cores',
        EM_RISCV          => 'RISC-V',
        EM_BPF            => 'Linux BPF - in-kernel virtual machine',
        EM_CSKY           => 'C-SKY',
        EM_LOONGARCH      => 'LoongArch',
        EM_FRV            => 'Fujitsu FR-V',
        EM_ALPHA          => 'Alpha',
        EM_CYGNUS_M32R    => 'Bogus old m32r magic number, used by old tools',
        EM_S390_OLD       => 'Old S/390 architecture',
        EM_CYGNUS_MN10300 => 'Panasonic/MEI MN10300, AM33',
    );

    return $machine_names{$e_machine} || 'Unknown';
}

1;
