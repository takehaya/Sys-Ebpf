package ebpf::loader;

use strict;
use warnings;

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

sub load {
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

sub attach_bpf_map {
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
        $insn_cnt, $license, $log_buf, length($log_buf));

    if ($fd < 0) {
        print Dumper($log_buf);
        die "BPF program load failed: $fd\n";
    }

    print "BPF program loaded successfully with FD: $fd\n";

    return $fd;
}

# r_offsetを使って、修正すべき命令（インストラクション）をkprobe/sys_execveセクション内から特定します。
# r_infoからシンボルインデックスを取得し、そのシンボルのアドレスをシンボルテーブル（.symtab）から取得します。
# 修正すべきインストラクションに、シンボルのアドレスを適用して、正しいマップへの参照に書き換えます。
sub apply_relocations {
    my ($self, $prob_section, $reloc_sections, $elf, $map_data) = @_;
    my $symbols_section = $elf->{symbols};
    for my $reloc_section (@$reloc_sections) {
        print "reloc_section: ", Dumper($reloc_section);
        my $r_info = $reloc_section->{r_info};
        my $r_offset = $reloc_section->{r_offset} + $prob_section->{sh_offset}; 

        my $sym_index = $r_info >> 32; # シンボルインデックスを取得
        my $reloc_type = $r_info & 0xFFFFFFFF; # リロケーションタイプを取得
        # シンボルテーブルからrelocation対象になり得るシンボル名を取得
        # print "sym_index: $sym_index\n";
        # print "symbols_section: ", Dumper($symbols_section);
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
            # my $bpf_insn = substr($self->{reader}->{raw_elf_data}, $r_offset, 16);
            # print "Before relocation (offset $r_offset): " . unpack('H*', $bpf_insn) . "\n";  # デバッグ出力
            # my ($code, $dst_src, $off, $imm_high, $imm_low) = unpack('CCsLL', $bpf_insn);

            # # マップFDを適切に設定（FDを64ビットに分割）
            # $imm_high = 0;  # 上位32ビットは0
            # $imm_low = $map_fd;  # 下位32ビットにFDを設定

            # # 新しい命令をパックして元の場所に書き戻す
            # my $new_bpf_insn = pack('CCsLL', $code, $dst_src, $off, $imm_high, $imm_low);
            # substr($self->{reader}->{raw_elf_data}, $r_offset, 16, $new_bpf_insn);
            #---
            # `lddw` の場合は16バイト分の命令を取得する
            # $r_offset += 8;
            my $bpf_insn = substr($self->{reader}->{raw_elf_data}, $r_offset, 16);  # 16バイトを取得
            print "Before relocation (offset $r_offset): " . unpack('H*', $bpf_insn) . "\n";  # デバッグ出力

            # 1つ目の命令は上位32ビット、2つ目の命令は下位32ビットの即値を含む
            my ($code1, $dst_src1, $off1, $imm_high, $code2, $dst_src2, $off2, $imm_low) = unpack('CCsLCCsL', $bpf_insn);

            # show debug
            print "code1=$code1, dst_src1=$dst_src1, off1=$off1, imm_high=$imm_high, code2=$code2, dst_src2=$dst_src2, off2=$off2, imm_low=$imm_low\n";  # デバッグ出力
            # マップFDを64ビットの即値として設定
            $imm_high = 0;  # 上位32ビットを0に
            $imm_low = $map_fd;  # 下位32ビットにFDを設定

            # 修正後の命令をパックして、元の場所に書き戻す
            my $new_bpf_insn = pack('CCsLCCsL', $code1, $dst_src1, $off1, $imm_high, $code2, $dst_src2, $off2, $imm_low);
            substr($self->{reader}->{raw_elf_data}, $r_offset, 16, $new_bpf_insn);  # 16バイト書き戻す

            # 書き換えた後の命令を出力
            my $after_bpf_insn = substr($self->{reader}->{raw_elf_data}, $r_offset, 16);
            print "After relocation (offset $r_offset): " . unpack('H*', $after_bpf_insn) . "\n";  # デバッグ出力
            # debug end

          # 指定されたオフセット位置にあるBPF命令（8バイト）を取得
            # my $bpf_insn = substr($self->{reader}->{raw_elf_data}, $r_offset, 8);
            # my ($code, $dst_src, $off, $imm) = unpack('CCsL', $bpf_insn);

            # print "Before relocation: code=$code, dst_src=$dst_src, off=$off, imm=$imm\n";
            # if ($imm != 0){
            #     print "imm is not 0\n";
            #     next;
            # }
            # # `imm` フィールドを書き換える（マップFDを適用）
            # $imm = $map_fd;

            # # 新しい命令をパックして元の場所に書き戻す
            # my $new_bpf_insn = pack('CCsL', $code, $dst_src, $off, $imm);
            # substr($self->{reader}->{raw_elf_data}, $r_offset, 8, $new_bpf_insn);

            # # 変更後のデータを確認
            # my $after_bpf_insn = substr($self->{reader}->{raw_elf_data}, $r_offset, 8);
            # my ($new_code, $new_dst_src, $new_off, $new_imm) = unpack('CCsL', $after_bpf_insn);
            # print "After relocation: code=$new_code, dst_src=$new_dst_src, off=$new_off, imm=$new_imm\n";

        } else {
            print "No matching map found for symbol: $sym_name\n";
        }
    }
    print "Final instructions:\n";
}

sub attach_bpf {
    my ($self, $section_name) = @_;
    my $bpfelf = $self->{bpfelf};

    # BPF マップをロード(あとでlistにする)
    my $map_name = "kprobe_map";
    my $map_fd = $self->attach_bpf_map($map_name, 1, 4, 8, 1, 0);

    # print Dumper($bpfelf->{sections});
    # print Dumper($bpfelf->{relocations});
    # リロケーションを適用
    print ".rel" . $section_name . "\n";
    my $reloc_section = $bpfelf->{relocations}{".rel" . $section_name};
    my $prob_section = find_symbol_table_from_name($bpfelf->{sections}, $section_name);
    if (defined $reloc_section) {
        $self->apply_relocations($prob_section, $reloc_section, $bpfelf, [[$map_name, $map_fd]]);
    }
   
    # BPF プログラムをロード
    my $prog_fd = $self->attach_bpf_program($section_name);

    return ($map_fd, $prog_fd);
}

1;