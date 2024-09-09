package ebpf::loader;

use strict;
use warnings;

use ebpf::asm;
use ebpf::reader;
use ebpf::c_bpf_loader;

use Data::Dumper;

use ebpf::elf::section_type qw(SHT_PROGBITS);
use ebpf::constants::bpf_cmd qw(BPF_MAP_CREATE BPF_PROG_LOAD);
use ebpf::constants::bpf_prog_type qw(BPF_PROG_TYPE_KPROBE);
use ebpf::elf::section_type qw(SHT_RELA SHT_REL SHT_SYMTAB);

# use lib '../../lib';
require 'ebpf/syscall/sys/syscall.ph';

sub new {
    my ($class, $file) = @_;
    my $self = { file => $file };
    bless $self, $class;
    return $self;
}

sub load_elf {
    my ($self) = @_;
    my $file = $self->{file};

    my $reader = ebpf::reader->new($file);
    $self->{reader} = $reader;
    
    my $bpfelf = $reader->parse_ebpf();
    $self->{bpfelf} = $bpfelf;

    return $bpfelf;
}

sub find_symbol_table_from_idx {
    my ($symbols, $idx) = @_;
    for my $symbol (@$symbols) {
        if ($symbol->{st_shndx} == $idx) {
            return $symbol;
        }
    }
    return undef;
}

sub find_symbol_table_from_name {
    my ($symbols, $name) = @_;
    for my $symbol (@$symbols) {
        if ($symbol->{sh_name} eq $name) {
            return $symbol;
        }
    }
    return undef;
}

sub load_bpf_map {
    my ($self, $map_name, $map_type, $key_size, $value_size, $max_entries, $map_flags) = @_;
    my $bpfelf = $self->{bpfelf};

    # 適切なセクションを取得して BPF マップを準備
    my $bpf_section;
    for my $section (@{$bpfelf->{sections}}) {
        if ($section->{sh_type} == SHT_PROGBITS 
        && $section->{sh_name} eq "maps") {
            $bpf_section = $section;
            last;
        }
    }
    unless ($bpf_section) {
        die "BPF map section not found in ELF file.";
    }

    # BPF マップ属性を設定
    # cf. https://docs.kernel.org/userspace-api/ebpf/syscall.html
    # BPF マップをロードするための構造体をパック
    # 後でいい感じに整える。。。
    my $bpf_map = substr($self->{reader}->{raw_elf_data}, $bpf_section->{sh_offset}, $bpf_section->{sh_size});

    # BPF マップを作成
    print "map_type: $map_type". "key_size: $key_size" ."\n";
    my $fd = ebpf::c_bpf_loader::load_bpf_map($map_type, $key_size, $value_size, $max_entries, $map_flags);

    if ($fd < 0) {
        die "BPF map load failed: $fd\n";
    }

    print "BPF map loaded successfully with FD: $fd\n";

    return $fd;
}

sub attach_bpf_program {
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

    print "bpf_section: ", Dumper($bpf_section);
    print Dumper($bpf_prog);

    print "After relocation:\n";
    for (my $i = 0; $i < $insn_cnt; $i++) {
        my $insn = substr($bpf_prog, $i * 8, 8);
        print unpack('H*', $insn) . "\n";  # バイナリ命令を16進数で出力
    }

    # バッファを適切に初期化
    my $log_buf = "\0" x 4096 x 2;  # ログバッファを適切なサイズで初期化
    my $license = "GPL";

    my $fd = ebpf::c_bpf_loader::load_bpf_program(
        BPF_PROG_TYPE_KPROBE, 
        $bpf_prog, 
        $insn_cnt, $license, 
        3, # log level
        $log_buf, 
        length($log_buf));

    if ($fd < 0) {
        print Dumper($log_buf);
        die "BPF program load failed: $fd\n";
    }

    print "BPF program loaded successfully with FD: $fd\n";

    return $fd;
}

sub pin_bpf_map {
    my ($map_fd, $pin_path) = @_;

    # bpf_obj_pin syscallを呼び出してマップを指定のパスに保存する
    my $res = ebpf::c_bpf_loader::pin_bpf_map($map_fd, $pin_path);

    if ($res < 0) {
        die "Failed to pin BPF map: $res\n";
    }

    print "BPF map pinned successfully at $pin_path\n";
}

sub unpin_bpf_map {
    my ($pin_path) = @_;

    # ファイルを削除する
    if (unlink($pin_path)) {
        print "BPF map unpinned successfully from $pin_path\n";
    } else {
        die "BPF map unpinning failed: $!\n";
    }
}

# リロケーションを適用
# args:
#   prob_section: プログラムセクション
#   reloc_sections: リロケーションセクション
#   elf: ELFデータ
#   map_data: マップデータのリファレンス
# r_offsetを使って、修正すべき命令（インストラクション）をkprobe/sys_execveセクション内から特定します。
# r_infoからシンボルインデックスを取得し、そのシンボルのアドレスをシンボルテーブル（.symtab）から取得します。
# 修正すべきインストラクションに、シンボルのアドレスを適用して、正しいマップへの参照に書き換えます。
sub apply_map_relocations {
    my ($self, $prob_section, $reloc_sections, $elf, $map_data) = @_;
    my $symbols_section = $elf->{symbols};
    for my $reloc_section (@$reloc_sections) {
        print "reloc_section: ", Dumper($reloc_section);
        my $r_info = $reloc_section->{r_info};
        my $r_offset = $reloc_section->{r_offset} + $prob_section->{sh_offset}; 

        my $sym_index = $r_info >> 32; # シンボルインデックスを取得
        my $reloc_type = $r_info & 0xFFFFFFFF; # リロケーションタイプを取得
        
        # シンボルテーブルからrelocation対象になり得るシンボル名を取得
        my $symbol = find_symbol_table_from_idx($symbols_section, $sym_index);
        if (!$symbol) {
            print "Symbol not found for index: $sym_index\n";
            next;
        }
        my $sym_name = $symbol->{st_name};
        if ($symbol->{st_shndx} == 0) {
            print "Symbol not found for index: $sym_index\n";
            next;
        }
        
        # `$map_data` の中のタプルを確認して、期待してるマップ名が存在するかチェック(fdを取得)
        print "find map: $sym_name\n";
        my $map_fd = undef;
        for my $tuple (@$map_data) {
            print "tuple: ", Dumper($tuple);
            my ($map_name, $fd) = @$tuple;
            if ($sym_name eq $map_name) {
                $map_fd = $fd;
                last;  # マップが見つかったらループを抜ける
            }
        }

        print "Symbol: $sym_name, Map FD: $map_fd\n";
        if (defined $map_fd) {    
            # --- ここから追加 ---
            # # 指定されたオフセット位置にある `lddw` 命令（16バイト）を取得
            my $bpf_insn = substr($self->{reader}->{raw_elf_data}, $r_offset, 16);  # 16バイトを取得
            my $bpf_insn_len = length($bpf_insn);
            print "Before relocation (offset $r_offset): " . unpack('H*', $bpf_insn) . "\n";  # デバッグ出力

            my ($high, $low) = ebpf::asm::deserialize_128bit_instruction($bpf_insn);

            # 即値 (64ビット) にマップFDを設定
            $high->set_imm($map_fd);
            $low->set_imm($map_fd>>32);

            # src_reg に PSEUDO_MAP_FD (1) を設定
            $high->set_src_reg(1);

            # 修正後の命令をパックして、元の場所に書き戻す
            my $new_bpf_insn = ebpf::asm::serialize_128bit_instruction($high, $low);
            substr($self->{reader}->{raw_elf_data}, $r_offset, 16, $new_bpf_insn);

            # 書き換えた後の命令を出力
            my $after_bpf_insn = substr($self->{reader}->{raw_elf_data}, $r_offset, 16);
            print "After relocation (offset $r_offset): " . unpack('H*', $after_bpf_insn) . "\n";  # デバッグ出力
        } else {
            print "No matching map found for symbol: $sym_name\n";
        }
    }
    print "Final instructions:\n";
}

# BPF プログラムとマップをロード
# args:
#   section_name: BPF プログラムのセクション名
#   map_attr_ref: マップ名と属性の組になったhashのリファレンス
# return:
#   map_data: マップ名とFDの組になったhashのリファレンス
#   prog_fd: プログラムFD
sub load_bpf {
    my ($self, $section_name, $map_attr_ref) = @_;
    my $bpfelf = $self->{bpfelf};
    my %map_attr = %$map_attr_ref;

    my @map_data;
    # map_attr_refの各キー（マップ名）に対して処理を実行
    for my $map_name (keys %map_attr) {
        my $attr = $map_attr{$map_name};

        my $map_fd = $self->load_bpf_map(
            $map_name,
            $attr->{map_type} || 0,
            $attr->{key_size} || 0,
            $attr->{value_size} || 0,
            $attr->{max_entries} || 0,
            $attr->{map_flags} || 0,
        );
        if ($map_fd < 0) {
            die "Failed to load BPF map: $map_name (FD: $map_fd)\n";
        }
        push @map_data, [$map_name, $map_fd];
    }

    # リロケーションを適用
    print ".rel" . $section_name . "\n";
    my $reloc_section = $bpfelf->{relocations}{".rel" . $section_name};
    my $prob_section = find_symbol_table_from_name($bpfelf->{sections}, $section_name);
    if (defined $reloc_section) {
        $self->apply_map_relocations($prob_section, $reloc_section, $bpfelf, \@map_data);
    }

    # todo: bpfprobが複数あるケースにも対応する
    # BPF プログラムをロード
    my $prog_fd = $self->attach_bpf_program($section_name);

    return (\@map_data, $prog_fd);
}

1;