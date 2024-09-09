use strict;
use warnings;
use Test::More;

# Load the module you're testing
use lib '../lib';  # Adjust the path based on your module's location
# use lib '../../blib/arch/auto/ebpf/c_bpf_loader';
use ebpf::asm;

my $asm = ebpf::asm->new(
    code    => 0x18,       # opcode(lddw)
    dst_reg => 1,          # destination register (r1)
    src_reg => 1,          # source register(Pseudo map fd)
    off     => 0,          # offset
    imm     => 0x3  # immediate value (map fd)
);

my $serialized = $asm->serialize();
ok(length($serialized) == 8, "Serialized instruction is 8 bytes");
is(unpack('H*', $serialized), '1811000003000000', 'Serialized output is correct');

my $deserialized = ebpf::asm->deserialize($serialized);
is($deserialized->get_code(), 0x18, "Deserialized opcode matches");
is($deserialized->get_imm(), 3, "Deserialized immediate matches");
is($deserialized->get_src_reg(), 1, "Deserialized source register matches");
is($deserialized->get_dst_reg(), 1, "Deserialized destination register matches");

done_testing();
