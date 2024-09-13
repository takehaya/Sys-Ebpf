use strict;
use warnings;
use utf8;

use Test::More import => [qw( done_testing ok plan )];

use Sys::Ebpf::Asm;
use Sys::Ebpf::Loader;

use Sys::Ebpf::Constants::BpfProgType qw( BPF_PROG_TYPE_KPROBE );

plan skip_all => "This test must be run as root" if $> != 0;

my $loader = Sys::Ebpf::Loader->new("dummy.o");

my @program = (
    Sys::Ebpf::Asm::BPF_ALU64_IMM( Sys::Ebpf::Asm::BPF_MOV, 6, 1 ),  # r6 = 1
    Sys::Ebpf::Asm::BPF_ALU64_REG( Sys::Ebpf::Asm::BPF_MOV, 1, 6 ),  # r1 = r6
    Sys::Ebpf::Asm::BPF_ALU64_IMM( Sys::Ebpf::Asm::BPF_ADD, 1, 5 ),  # r1 += 5
    Sys::Ebpf::Asm::BPF_ALU64_REG( Sys::Ebpf::Asm::BPF_MOV, 0, 1 ),  # r0 = r1
    Sys::Ebpf::Asm::BPF_JMP_IMM( Sys::Ebpf::Asm::BPF_EXIT, 0, 0, 0 ),   # exit
);

my $serialized_program = Sys::Ebpf::Asm::serialize_sequence( \@program );

my $prog_fd = $loader->load_bpf_program(
    {   prog_type => BPF_PROG_TYPE_KPROBE,
        insn_cnt  => scalar(@program),
        insns     => $serialized_program,
        license   => "GPL\0",
        log_level => 1,
        log_buf   => "\0" x 4096,
        log_size  => 4096,
    }
);

ok( $prog_fd > 0, "Loaded eBPF program with fd $prog_fd" );

# Additional checks can be added here, such as verifying the returned file descriptor
# or checking the log buffer for specific messages

done_testing();

