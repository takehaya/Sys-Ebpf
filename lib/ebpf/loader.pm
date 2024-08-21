package ebpf::loader;

use strict;
use warnings;

use ebpf::reader;
use ebpf::elf::section_type qw(SHT_PROGBITS);

use lib '../../lib';
require 'ebpf/syscall/sys/syscall.ph';

sub new {
    my ($class, $file) = @_;
    my $self = { file => $file };
    bless $self, $class;
    return $self;
}

sub load {
    my ($self) = @_;
    my $file = $self->{file};

    my $reader = ebpf::reader->new($file);
    $self->{reader} = $reader;
    
    my $bpfelf = $reader->parse_ebpf();
    $self->{bpfelf} = $bpfelf;

    return $bpfelf;
}

sub attach_bpf {
    my ($self, $event, $handler) = @_;
    my $bpfelf = $self->{bpfelf};
  
    # 適切なセクションを取得して BPF プログラムを準備
    my $bpf_section;
    for my $section (@{$bpfelf->{sections}}) {
        if ($section->{sh_type} == SHT_PROGBITS) {
            $bpf_section = $section;
            last;
        }
    }
    print "bpf_section: $bpf_section\n";
    use Data::Dumper;
    print Dumper($bpf_section);
    unless ($bpf_section) {
        die "BPF program section not found in ELF file.";
    }

    # # BPF プログラムをカーネルにロード
    # my $bpf_prog = substr($self->{reader}->{data}, $bpf_section->{sh_offset}, $bpf_section->{sh_size});

    # my $bpf_prog_attr = pack("L L L L L L L L L L L L", 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); # ここはBPFプログラム属性の構造体に合わせる
    # my $result = syscall(
    #     SYS_bpf(),         # BPF システムコールの番号
    #     1,                 # BPF_PROG_LOAD コマンド
    #     $bpf_prog_attr,    # BPF プログラム属性へのポインタ
    #     length($bpf_prog_attr) # 構造体のサイズ
    # );

    # if ($result < 0) {
    #     die "BPF program load failed: $!";
    # }

    # syscalls bpf

    # return $bpf;
}


1;