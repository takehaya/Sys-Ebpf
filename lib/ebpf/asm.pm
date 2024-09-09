package ebpf::asm;

use strict;
use warnings;

sub new {
    my ($class, %args) = @_;
    
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

1;