use strict;
use warnings;
use utf8;

use Test::More import => [qw( done_testing ok plan )];

# Load the module you're testing
use lib '../lib';    # Adjust the path based on your module's location
use sys::ebpf::asm;
use sys::ebpf::loader;

use sys::ebpf::constants::bpf_prog_type qw( BPF_PROG_TYPE_KPROBE );

plan skip_all => "This test must be run as root" if $> != 0;

my $loader = sys::ebpf::loader->new("dummy.o");

my @program = (
    sys::ebpf::asm::BPF_ALU64_IMM( sys::ebpf::asm::BPF_MOV, 6, 1 ),  # r6 = 1
    sys::ebpf::asm::BPF_ALU64_REG( sys::ebpf::asm::BPF_MOV, 1, 6 ),  # r1 = r6
    sys::ebpf::asm::BPF_ALU64_IMM( sys::ebpf::asm::BPF_ADD, 1, 5 ),  # r1 += 5
    sys::ebpf::asm::BPF_ALU64_REG( sys::ebpf::asm::BPF_MOV, 0, 1 ),  # r0 = r1
    sys::ebpf::asm::BPF_JMP_IMM( sys::ebpf::asm::BPF_EXIT, 0, 0, 0 ),   # exit
);

my $serialized_program = sys::ebpf::asm::serialize_sequence( \@program );

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

