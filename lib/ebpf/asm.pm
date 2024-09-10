package ebpf::asm;

use strict;
use warnings;

our $VERSION = $ebpf::VERSION;

# cf. https://www.kernel.org/doc/html/v6.11-rc7/bpf/standardization/instruction-set.html
# cf. https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
# BPF instruction classes
use constant {
    BPF_LD    => 0x00,
    BPF_LDX   => 0x01,
    BPF_ST    => 0x02,
    BPF_STX   => 0x03,
    BPF_ALU   => 0x04,
    BPF_JMP   => 0x05,
    BPF_RET   => 0x06,
    BPF_MISC  => 0x07,
    BPF_ALU64 => 0x07,  # Added ALU64
};

# BPF LD/LDX size modifiers
use constant {
    BPF_W   => 0x00,
    BPF_H   => 0x08,
    BPF_B   => 0x10,
    BPF_DW  => 0x18,
};

# BPF LD/LDX mode modifiers
use constant {
    BPF_IMM  => 0x00,
    BPF_ABS  => 0x20,
    BPF_IND  => 0x40,
    BPF_MEM  => 0x60,
    BPF_XADD => 0xc0,
};

# BPF ALU operations
use constant {
    BPF_ADD  => 0x00,
    BPF_SUB  => 0x10,
    BPF_MUL  => 0x20,
    BPF_DIV  => 0x30,
    BPF_OR   => 0x40,
    BPF_AND  => 0x50,
    BPF_LSH  => 0x60,
    BPF_RSH  => 0x70,
    BPF_NEG  => 0x80,
    BPF_MOD  => 0x90,
    BPF_XOR  => 0xa0,
    BPF_MOV  => 0xb0,
    BPF_ARSH => 0xc0,
    BPF_END  => 0xd0,
};

# BPF JMP operations
use constant {
    BPF_JA   => 0x00,
    BPF_JEQ  => 0x10,
    BPF_JGT  => 0x20,
    BPF_JGE  => 0x30,
    BPF_JSET => 0x40,
    BPF_JNE  => 0x50,
    BPF_JSGT => 0x60,
    BPF_JSGE => 0x70,
    BPF_CALL => 0x80,
    BPF_EXIT => 0x90,
    BPF_JLT  => 0xa0,
    BPF_JLE  => 0xb0,
    BPF_JSLT => 0xc0,
    BPF_JSLE => 0xd0,
};

# BPF source operand
use constant {
    BPF_K => 0x00,
    BPF_X => 0x08,
};

sub new {
    my $class = shift;
    my %args;

    if (@_ == 1 && ref $_[0] eq 'HASH') {
        %args = %{$_[0]};
    } elsif (@_ == 5) {
        %args = (
            code     => $_[0],
            dst_reg  => $_[1],
            src_reg  => $_[2],
            off      => $_[3],
            imm      => $_[4],
        );
    } elsif (@_ % 2 == 0) {
        %args = @_;
    } else {
        die "Invalid arguments for constructor";
    }
    
    my $self = {
        code     => $args{code} || 0,
        dst_reg  => $args{dst_reg} || 0,
        src_reg  => $args{src_reg} || 0,
        off      => $args{off} || 0,
        imm      => $args{imm} || 0,
    };
    
    bless $self, $class;
    return $self;
}

sub serialize_sequence {
    my ($instructions_ref) = @_;
    my $serialized = '';
    for my $insn (@$instructions_ref) {
        $serialized .= $insn->serialize();
    }
    return $serialized;
}
sub serialize {
    my ($self) = @_;
    
    return pack('CCsL', 
        $self->{code}, 
        ($self->{src_reg} << 4)&0b11110000 | $self->{dst_reg}&0b00001111,
        $self->{off}, 
        $self->{imm}
    );
}

sub deserialize {
    my ($class, $raw_insn) = @_;

    die "Undefined instruction" unless defined $raw_insn;
    die "instruction too short" unless length($raw_insn) == 8;

    my ($code, $dst_src, $off, $imm) = unpack('CCsL', $raw_insn);
    
    my $self = {
        code     => $code,
        dst_reg  => $dst_src & 0b00001111,
        src_reg  => ($dst_src & 0b11110000)>>4,
        off      => $off,
        imm      => $imm,
    };
    
    bless $self, $class;
    return $self;
}

sub set_code     { $_[0]->{code} = $_[1] }
sub set_dst_reg  { $_[0]->{dst_reg} = $_[1] }
sub set_src_reg  { $_[0]->{src_reg} = $_[1] }
sub set_off      { $_[0]->{off} = $_[1] }
sub set_imm      { $_[0]->{imm} = $_[1] }

sub get_code     { $_[0]->{code} }
sub get_dst_reg  { $_[0]->{dst_reg} }
sub get_src_reg  { $_[0]->{src_reg} }
sub get_off      { $_[0]->{off} }
sub get_imm      { $_[0]->{imm} }


sub deserialize_128bit_instruction {
    my ($binary) = @_;

    my $high = ebpf::asm->deserialize(substr($binary, 0, 8));
    my $low = ebpf::asm->deserialize(substr($binary, 8, 8));

    return ($high, $low);
}

sub serialize_128bit_instruction {
    my ($high, $low) = @_;

    my $serialized_high = $high->serialize();
    my $serialized_low  = $low->serialize();

    return $serialized_high . $serialized_low;
}


## BPF instruction helpers

sub BPF_ALU32_REG {
    my ($OP, $DST, $SRC) = @_;
    return __PACKAGE__->new(
        code    => BPF_ALU | $OP | BPF_X,
        dst_reg => $DST,
        src_reg => $SRC,
    );
}

sub BPF_ALU32_IMM {
    my ($OP, $DST, $IMM) = @_;
    return __PACKAGE__->new(
        code    => BPF_ALU | $OP | BPF_K,
        dst_reg => $DST,
        imm     => $IMM,
    );
}

sub BPF_ALU64_REG {
    my ($OP, $DST, $SRC) = @_;
    return __PACKAGE__->new(
        code    => BPF_ALU64 | $OP | BPF_X,
        dst_reg => $DST,
        src_reg => $SRC,
    );
}

sub BPF_ALU64_IMM {
    my ($OP, $DST, $IMM) = @_;
    return __PACKAGE__->new(
        code    => BPF_ALU64 | $OP | BPF_K,
        dst_reg => $DST,
        imm     => $IMM,
    );
}

sub BPF_JMP_REG {
    my ($OP, $DST, $SRC, $OFF) = @_;
    return __PACKAGE__->new(
        code    => BPF_JMP | $OP | BPF_X,
        dst_reg => $DST,
        src_reg => $SRC,
        off     => $OFF,
    );
}

sub BPF_JMP_IMM {
    my ($OP, $DST, $IMM, $OFF) = @_;
    return __PACKAGE__->new(
        code    => BPF_JMP | $OP | BPF_K,
        dst_reg => $DST,
        imm     => $IMM,
        off     => $OFF,
    );
}

sub BPF_LD_IMM32 {
    my ($DST, $IMM) = @_;
    return __PACKAGE__->new(
        code    => BPF_ALU | BPF_MOV | BPF_K,
        dst_reg => $DST,
        imm     => $IMM & 0xFFFFFFFF,
    );
}

sub BPF_LD_IMM64 {
    my ($DST, $IMM) = @_;
    my $high = __PACKAGE__->new(
        code    => BPF_LD | BPF_DW | BPF_IMM,
        dst_reg => $DST,
        imm     => $IMM & 0xFFFFFFFF,
    );
    my $low = __PACKAGE__->new(
        imm     => $IMM >> 32,
    );
    return ($high, $low);
}
1;