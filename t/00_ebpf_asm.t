use strict;
use warnings;
use utf8;

use Test::More import => [qw( done_testing is is_deeply ok subtest )];

# Load the module you're testing
use Sys::Ebpf::Asm ();

subtest 'Test Sys::Ebpf::Asm basic functionality' => sub {
    my $Asm = Sys::Ebpf::Asm->new(
        code    => 0x18,    # opcode(lddw)
        dst_reg => 0x2,     # destination register (r2)
        src_reg => 0x1,     # source register(Pseudo map fd)
        off     => 0,       # offset
        imm     => 0x3      # immediate value (map fd)
    );

    my $serialized = $Asm->serialize();
    ok( length($serialized) == 8, "Serialized instruction is 8 bytes" );
    is( unpack( 'H*', $serialized ),
        '1812000003000000',
        'Serialized output is correct'
    );

    my $deserialized = Sys::Ebpf::Asm->deserialize($serialized);
    is( $deserialized->get_code(), 0x18, "Deserialized opcode matches" );
    is( $deserialized->get_imm(),  3,    "Deserialized immediate matches" );
    is( $deserialized->get_dst_reg(),
        2, "Deserialized destination register matches" );
    is( $deserialized->get_src_reg(),
        1, "Deserialized source register matches" );
};

subtest 'Test Sys::Ebpf::Asm constructors' => sub {
    my $Asm1 = Sys::Ebpf::Asm->new( 0x18, 0x2, 0x1, 0, 0x3 );
    my $Asm2 = Sys::Ebpf::Asm->new(
        {   code    => 0x18,
            dst_reg => 0x2,
            src_reg => 0x1,
            off     => 0,
            imm     => 0x3
        }
    );
    my $Asm3 = Sys::Ebpf::Asm->new(
        code    => 0x18,
        dst_reg => 0x2,
        src_reg => 0x1,
        off     => 0,
        imm     => 0x3
    );

    is_deeply( $Asm1, $Asm2,
        "Ordered parameters constructor matches hash ref constructor" );
    is_deeply( $Asm1, $Asm3,
        "Ordered parameters constructor matches named parameters constructor"
    );
};

subtest 'Test Sys::Ebpf::Asm macros add' => sub {

    # add64 r1, r2
    # This means: r1 += r2 (64-bit addition)
    my $add_reg
        = Sys::Ebpf::Asm::BPF_ALU64_REG( Sys::Ebpf::Asm::BPF_ADD, 1, 2 );
    is( $add_reg->get_code,
        Sys::Ebpf::Asm::BPF_ALU64 | Sys::Ebpf::Asm::BPF_ADD
            | Sys::Ebpf::Asm::BPF_X,
        'ALU64 REG ADD code is correct'
    );
    is( $add_reg->get_dst_reg, 1, 'ALU64 REG ADD dst_reg is correct' );
    is( $add_reg->get_src_reg, 2, 'ALU64 REG ADD src_reg is correct' );

    # add64 r1, 100
    # This means: r1 += 100 (64-bit immediate addition)
    my $add_imm
        = Sys::Ebpf::Asm::BPF_ALU64_IMM( Sys::Ebpf::Asm::BPF_ADD, 1, 100 );
    is( $add_imm->get_code,
        Sys::Ebpf::Asm::BPF_ALU64 | Sys::Ebpf::Asm::BPF_ADD
            | Sys::Ebpf::Asm::BPF_K,
        'ALU64 IMM ADD code is correct'
    );
    is( $add_imm->get_dst_reg, 1,   'ALU64 IMM ADD dst_reg is correct' );
    is( $add_imm->get_imm,     100, 'ALU64 IMM ADD imm is correct' );

    # add32 r1, r2
    # This means: r1 += r2 (32-bit addition)
    my $alu32_reg
        = Sys::Ebpf::Asm::BPF_ALU32_REG( Sys::Ebpf::Asm::BPF_ADD, 1, 2 );
    is( $alu32_reg->get_code,
        Sys::Ebpf::Asm::BPF_ALU | Sys::Ebpf::Asm::BPF_ADD
            | Sys::Ebpf::Asm::BPF_X,
        'ALU32 REG ADD code is correct'
    );
    is( $alu32_reg->get_dst_reg, 1, 'ALU32 REG ADD dst_reg is correct' );
    is( $alu32_reg->get_src_reg, 2, 'ALU32 REG ADD src_reg is correct' );

    # add32 r1, 100
    # This means: r1 += 100 (32-bit immediate addition)
    my $alu32_imm
        = Sys::Ebpf::Asm::BPF_ALU32_IMM( Sys::Ebpf::Asm::BPF_ADD, 1, 100 );
    is( $alu32_imm->get_code,
        Sys::Ebpf::Asm::BPF_ALU | Sys::Ebpf::Asm::BPF_ADD
            | Sys::Ebpf::Asm::BPF_K,
        'ALU32 IMM ADD code is correct'
    );
    is( $alu32_imm->get_dst_reg, 1,   'ALU32 IMM ADD dst_reg is correct' );
    is( $alu32_imm->get_imm,     100, 'ALU32 IMM ADD imm is correct' );
};

subtest 'Test Sys::Ebpf::Asm macros load' => sub {

    # mov r1, 0x12345678
    # This means: Load 32-bit immediate value 0x12345678 into r1
    my $ld_imm32 = Sys::Ebpf::Asm::BPF_LD_IMM32( 1, 0x12345678 );
    is( $ld_imm32->get_code,
        Sys::Ebpf::Asm::BPF_ALU | Sys::Ebpf::Asm::BPF_MOV
            | Sys::Ebpf::Asm::BPF_K,
        'LD_IMM32 code is correct'
    );
    is( $ld_imm32->get_dst_reg, 1,          'LD_IMM32 dst_reg is correct' );
    is( $ld_imm32->get_imm,     0x12345678, 'LD_IMM32 imm is correct' );

    # lddw r1, 0x1122334455667788
    # This means: Load 64-bit immediate value into r1
    # todo: not portable across 32-bit and 64-bit systems(fixme use bigint)
    my ( $high, $low )
        = Sys::Ebpf::Asm::BPF_LD_IMM64( 1, 0x1122334455667788 );
    is( $high->get_code,
        Sys::Ebpf::Asm::BPF_LD | Sys::Ebpf::Asm::BPF_DW
            | Sys::Ebpf::Asm::BPF_IMM,
        'LD_IMM64 high code is correct'
    );
    is( $high->get_dst_reg, 1,          'LD_IMM64 high dst_reg is correct' );
    is( $high->get_imm,     0x55667788, 'LD_IMM64 high imm is correct' );
    is( $low->get_imm,      0x11223344, 'LD_IMM64 low imm is correct' );
};

subtest 'Test Sys::Ebpf::Asm macros sub' => sub {

    # sub64 r1, r2
    # This means: r1 -= r2 (64-bit subtraction)
    my $sub64_reg
        = Sys::Ebpf::Asm::BPF_ALU64_REG( Sys::Ebpf::Asm::BPF_SUB, 1, 2 );
    is( $sub64_reg->get_code,
        Sys::Ebpf::Asm::BPF_ALU64 | Sys::Ebpf::Asm::BPF_SUB
            | Sys::Ebpf::Asm::BPF_X,
        'ALU64 REG SUB code is correct'
    );
    is( $sub64_reg->get_dst_reg, 1, 'ALU64 REG SUB dst_reg is correct' );
    is( $sub64_reg->get_src_reg, 2, 'ALU64 REG SUB src_reg is correct' );

    # sub64 r1, 100
    # This means: r1 -= 100 (64-bit immediate subtraction)
    my $sub64_imm
        = Sys::Ebpf::Asm::BPF_ALU64_IMM( Sys::Ebpf::Asm::BPF_SUB, 1, 100 );
    is( $sub64_imm->get_code,
        Sys::Ebpf::Asm::BPF_ALU64 | Sys::Ebpf::Asm::BPF_SUB
            | Sys::Ebpf::Asm::BPF_K,
        'ALU64 IMM SUB code is correct'
    );
    is( $sub64_imm->get_dst_reg, 1,   'ALU64 IMM SUB dst_reg is correct' );
    is( $sub64_imm->get_imm,     100, 'ALU64 IMM SUB imm is correct' );

    # sub32 r1, r2
    # This means: r1 -= r2 (32-bit subtraction)
    my $sub32_reg
        = Sys::Ebpf::Asm::BPF_ALU32_REG( Sys::Ebpf::Asm::BPF_SUB, 1, 2 );
    is( $sub32_reg->get_code,
        Sys::Ebpf::Asm::BPF_ALU | Sys::Ebpf::Asm::BPF_SUB
            | Sys::Ebpf::Asm::BPF_X,
        'ALU32 REG SUB code is correct'
    );
    is( $sub32_reg->get_dst_reg, 1, 'ALU32 REG SUB dst_reg is correct' );
    is( $sub32_reg->get_src_reg, 2, 'ALU32 REG SUB src_reg is correct' );

    # sub32 r1, 100
    # This means: r1 -= 100 (32-bit immediate subtraction)
    my $sub32_imm
        = Sys::Ebpf::Asm::BPF_ALU32_IMM( Sys::Ebpf::Asm::BPF_SUB, 1, 100 );
    is( $sub32_imm->get_code,
        Sys::Ebpf::Asm::BPF_ALU | Sys::Ebpf::Asm::BPF_SUB
            | Sys::Ebpf::Asm::BPF_K,
        'ALU32 IMM SUB code is correct'
    );
    is( $sub32_imm->get_dst_reg, 1,   'ALU32 IMM SUB dst_reg is correct' );
    is( $sub32_imm->get_imm,     100, 'ALU32 IMM SUB imm is correct' );
};

subtest 'Test Sys::Ebpf::Asm macros mul' => sub {

    # mul32 r1, r2
    # This means: r1 *= r2 (32-bit multiplication)
    my $mul32_reg
        = Sys::Ebpf::Asm::BPF_ALU32_REG( Sys::Ebpf::Asm::BPF_MUL, 1, 2 );
    is( $mul32_reg->get_code,
        Sys::Ebpf::Asm::BPF_ALU | Sys::Ebpf::Asm::BPF_MUL
            | Sys::Ebpf::Asm::BPF_X,
        'ALU32 REG MUL code is correct'
    );
    is( $mul32_reg->get_dst_reg, 1, 'ALU32 REG MUL dst_reg is correct' );
    is( $mul32_reg->get_src_reg, 2, 'ALU32 REG MUL src_reg is correct' );

    # mul64 r1, r2
    # This means: r1 *= r2 (64-bit multiplication)
    my $mul64_reg
        = Sys::Ebpf::Asm::BPF_ALU64_REG( Sys::Ebpf::Asm::BPF_MUL, 1, 2 );
    is( $mul64_reg->get_code,
        Sys::Ebpf::Asm::BPF_ALU64 | Sys::Ebpf::Asm::BPF_MUL
            | Sys::Ebpf::Asm::BPF_X,
        'ALU64 REG MUL code is correct'
    );
    is( $mul64_reg->get_dst_reg, 1, 'ALU64 REG MUL dst_reg is correct' );
    is( $mul64_reg->get_src_reg, 2, 'ALU64 REG MUL src_reg is correct' );
};

subtest 'Test Sys::Ebpf::Asm macros div' => sub {

    # div32 r1, 4
    # This means: r1 /= 4 (32-bit division by immediate)
    my $div32_imm
        = Sys::Ebpf::Asm::BPF_ALU32_IMM( Sys::Ebpf::Asm::BPF_DIV, 1, 4 );
    is( $div32_imm->get_code,
        Sys::Ebpf::Asm::BPF_ALU | Sys::Ebpf::Asm::BPF_DIV
            | Sys::Ebpf::Asm::BPF_K,
        'ALU32 IMM DIV code is correct'
    );
    is( $div32_imm->get_dst_reg, 1, 'ALU32 IMM DIV dst_reg is correct' );
    is( $div32_imm->get_imm,     4, 'ALU32 IMM DIV imm is correct' );

    # div64 r1, 4
    # This means: r1 /= 4 (64-bit division by immediate)
    my $div64_imm
        = Sys::Ebpf::Asm::BPF_ALU64_IMM( Sys::Ebpf::Asm::BPF_DIV, 1, 4 );
    is( $div64_imm->get_code,
        Sys::Ebpf::Asm::BPF_ALU64 | Sys::Ebpf::Asm::BPF_DIV
            | Sys::Ebpf::Asm::BPF_K,
        'ALU64 IMM DIV code is correct'
    );
    is( $div64_imm->get_dst_reg, 1, 'ALU64 IMM DIV dst_reg is correct' );
    is( $div64_imm->get_imm,     4, 'ALU64 IMM DIV imm is correct' );
};

subtest 'Test Sys::Ebpf::Asm macros cond' => sub {

    # jeq r1, 0, +5
    # This means: if (r1 == 0) jump +5 instructions
    my $jmp_eq
        = Sys::Ebpf::Asm::BPF_JMP_IMM( Sys::Ebpf::Asm::BPF_JEQ, 1, 0, 5 );
    is( $jmp_eq->get_code,
        Sys::Ebpf::Asm::BPF_JMP | Sys::Ebpf::Asm::BPF_JEQ
            | Sys::Ebpf::Asm::BPF_K,
        'JMP IMM JEQ code is correct'
    );
    is( $jmp_eq->get_dst_reg, 1, 'JMP IMM JEQ dst_reg is correct' );
    is( $jmp_eq->get_imm,     0, 'JMP IMM JEQ imm is correct' );
    is( $jmp_eq->get_off,     5, 'JMP IMM JEQ off is correct' );

    # jeq r1, r2, +5
    # This means: if (r1 == r2) jump +5 instructions
    my $jmp_reg
        = Sys::Ebpf::Asm::BPF_JMP_REG( Sys::Ebpf::Asm::BPF_JEQ, 1, 2, 5 );
    is( $jmp_reg->get_code,
        Sys::Ebpf::Asm::BPF_JMP | Sys::Ebpf::Asm::BPF_JEQ
            | Sys::Ebpf::Asm::BPF_X,
        'JMP REG JEQ code is correct'
    );
    is( $jmp_reg->get_dst_reg, 1, 'JMP REG JEQ dst_reg is correct' );
    is( $jmp_reg->get_src_reg, 2, 'JMP REG JEQ src_reg is correct' );
    is( $jmp_reg->get_off,     5, 'JMP REG JEQ off is correct' );

    # jgt r1, r2, +5
    # This means: if (r1 > r2) jump +5 instructions
    my $jmp_gt_reg
        = Sys::Ebpf::Asm::BPF_JMP_REG( Sys::Ebpf::Asm::BPF_JGT, 1, 2, 5 );
    is( $jmp_gt_reg->get_code,
        Sys::Ebpf::Asm::BPF_JMP | Sys::Ebpf::Asm::BPF_JGT
            | Sys::Ebpf::Asm::BPF_X,
        'JMP REG JGT code is correct'
    );

    # jlt r1, 10, +5
    # This means: if (r1 < 10) jump +5 instructions
    my $jmp_lt_imm
        = Sys::Ebpf::Asm::BPF_JMP_IMM( Sys::Ebpf::Asm::BPF_JLT, 1, 10, 5 );
    is( $jmp_lt_imm->get_code,
        Sys::Ebpf::Asm::BPF_JMP | Sys::Ebpf::Asm::BPF_JLT
            | Sys::Ebpf::Asm::BPF_K,
        'JMP IMM JLT code is correct'
    );
    is( $jmp_lt_imm->get_imm, 10, 'JMP IMM JLT imm is correct' );
};

done_testing();
