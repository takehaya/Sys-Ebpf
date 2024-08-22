package ebpf::loader;

use strict;
use warnings;

use ebpf::reader;
use ebpf::c_bpf_loader;

use ebpf::elf::section_type qw(SHT_PROGBITS);
use ebpf::constants::bpf_cmd qw(BPF_MAP_CREATE BPF_PROG_LOAD);
use ebpf::constants::bpf_prog_type qw(BPF_PROG_TYPE_KPROBE);

# use lib '../../lib';
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
    my ($self, $section_name) = @_;
    my $bpfelf = $self->{bpfelf};
  
    # 適切なセクションを取得して BPF プログラムを準備
    my $bpf_section;
    for my $section (@{$bpfelf->{sections}}) {
        print "section: $section->{sh_name}\n";
        if ($section->{sh_type} == SHT_PROGBITS 
        && $section->{sh_name} eq $section_name) {
            $bpf_section = $section;
            last;
        }
    }
    unless ($bpf_section) {
        die "BPF program section not found in ELF file.";
    }


    # BPF プログラム属性を設定
    # cf. https://docs.kernel.org/userspace-api/ebpf/syscall.html
    # BPF プログラムをロードするための構造体をパック
    # 後でいい感じに整える。。。
    my $bpf_prog = substr($self->{reader}->{raw_elf_data}, $bpf_section->{sh_offset}, $bpf_section->{sh_size});
    my $insn_cnt = length($bpf_prog) / 8;  # BPF 命令は通常8バイト

    use Data::Dumper;
    print "bpf_section: ", Dumper($bpf_section);
    print Dumper($bpf_prog);

    # バッファを適切に初期化
    my $log_buf = "\0" x 4096 x 2;  # ログバッファを適切なサイズで初期化
    my $license = "GPL";

    # cf. https://elixir.bootlin.com/linux/v6.11-rc4/source/include/uapi/linux/bpf.h#L1528
    # my $bpf_prog_attr = pack("L L P L P L L P L L L L L L L L L L L L L L L L",
    #     BPF_PROG_TYPE_KPROBE,   # prog_type
    #     0,                      # name (未使用)
    #     $insn_cnt,              # insn_cnt
    #     unpack('L!', pack('P', $bpf_prog)), # insns ポインタを変換
    #     unpack('L!', pack('P', $license)),  # license ポインタを変換
    #     $kern_version,          # kern_version
    #     1,                      # log_level
    #     unpack('L!', pack('P', $log_buf)),  # log_buf ポインタを変換
    #     length($log_buf),       # log_size
    #     0,                      # prog_flags
    #     0,                      # prog_ifindex
    #     0,                      # expected_attach_type
    #     0,                      # prog_btf_fd
    #     0,                      # func_info_rec_size
    #     0,                      # func_info
    #     0,                      # func_info_cnt
    #     0,                      # line_info_rec_size
    #     0,                      # line_info
    #     0,                      # line_info_cnt
    #     0,                      # attach_btf_id
    #     0,                      # attach_prog_fd (union)
    #     0,                      # attach_btf_obj_fd (union)
    #     0                       # no_prealloc
    # );
    # my $result = syscall(
    #     SYS_bpf(),
    #     BPF_PROG_LOAD,
    #     $bpf_prog_attr,    # BPF プログラム属性へのポインタ
    #     length($bpf_prog_attr) # 構造体のサイズ
    # );
    my $fd = ebpf::c_bpf_loader::load_bpf_program(
        BPF_PROG_TYPE_KPROBE, 
        $bpf_prog, 
        $insn_cnt, $license, $log_buf, length($log_buf));

    if ($fd < 0) {
        print Dumper($log_buf);
        die "BPF program load failed: $fd\n";
    }

    print "BPF program loaded successfully with FD: $fd\n";

    return $fd;
}


1;