package sys::ebpf::loader;

use strict;
use warnings;
use utf8;

use sys::ebpf::asm;
use sys::ebpf::reader ();
use sys::ebpf::map;
our $VERSION = $sys::ebpf::VERSION;

use Data::Dumper ();

use sys::ebpf::elf::section_type        qw( SHT_PROGBITS );
use sys::ebpf::constants::bpf_cmd       qw( BPF_PROG_LOAD );
use sys::ebpf::constants::bpf_prog_type qw( BPF_PROG_TYPE_KPROBE );
use sys::ebpf::elf::section_type        qw( SHT_PROGBITS );
use sys::ebpf::elf::symbol_type         qw(STT_OBJECT);
use Errno                               qw( EACCES EPERM );
use sys::ebpf::syscall;

sub new {
    my ( $class, $file ) = @_;
    my $self = { file => $file };
    bless $self, $class;
    return $self;
}

sub load_elf {
    my ($self) = @_;
    my $file = $self->{file};

    my $reader = sys::ebpf::reader->new($file);
    $self->{reader} = $reader;

    my $bpfelf = $reader->parse_ebpf();
    $self->{bpfelf} = $bpfelf;

    return $bpfelf;
}

sub find_symbol_table_from_idx {
    my ( $symbols, $idx ) = @_;
    for my $symbol (@$symbols) {
        if ( $symbol->{st_shndx} == $idx ) {
            return $symbol;
        }
    }
    return undef;
}

sub find_symbol_table_from_name {
    my ( $symbols, $name ) = @_;
    for my $symbol (@$symbols) {
        if ( $symbol->{sh_name} eq $name ) {
            return $symbol;
        }
    }
    return undef;
}

sub extract_bpf_map_attributes {
    my ( $self, $section_name ) = @_;
    my $bpfelf = $self->{bpfelf};

    # find map section
    my $map_section;
    for my $section ( @{ $bpfelf->{sections} } ) {
        if (   $section->{sh_type} == SHT_PROGBITS
            && $section->{sh_name} eq $section_name )
        {
            $map_section = $section;
            last;
        }
    }

    die "BPF map section '$section_name' not found in ELF file."
        unless $map_section;

    my $map_data = substr(
        $self->{reader}->{raw_elf_data},
        $map_section->{sh_offset},
        $map_section->{sh_size}
    );

    # parse map attributes
    my @maps;
    my $offset = 0;
    while ( $offset < length($map_data) ) {

        # map size is 20 bytes
        my ( $map_type, $key_size, $value_size, $max_entries, $map_flags )
            = unpack( "L L L L L", substr( $map_data, $offset, 20 ) );
        push @maps,
            {
            map_type    => $map_type,
            key_size    => $key_size,
            value_size  => $value_size,
            max_entries => $max_entries,
            map_flags   => $map_flags,
            };
        $offset += 20;
    }

    # get map names
    ## map sectionのidxと一致するst_shndxを持つシンボルを取得
    my %map_names;
    for my $symbol ( @{ $bpfelf->{symbols} } ) {
        if ( ( $symbol->{st_info} & 0xf ) != STT_OBJECT ) {
            next;
        }
        if ( $symbol->{st_shndx} == $map_section->{sh_index} ) {
            my $map_index = $symbol->{st_value} / 20;
            $map_names{$map_index} = $symbol->{st_name};
        }
    }
    for my $i ( 0 .. $#maps ) {
        $maps[$i]{map_name} = $map_names{$i} if exists $map_names{$i};
    }
    return \@maps;
}

sub find_section {
    my ( $self, $section_name ) = @_;
    my $bpfelf = $self->{bpfelf};
    return sys::ebpf::elf::parser::find_section( $bpfelf->{sections},
        $section_name );
}

sub load_bpf_program_from_elf {
    my ( $self, $section_name ) = @_;
    my $bpfelf      = $self->{bpfelf};
    my $bpf_section = $self->find_section($section_name);
    if ( !$bpf_section ) {
        die "BPF program section '$section_name' not found in ELF file.";
    }

    my $license_section = $self->find_section("license");
    if ( !$license_section ) {
        die "'license' section not found in ELF file.";
    }

    # BPF プログラム属性を設定
    # cf. https://docs.kernel.org/userspace-api/ebpf/syscall.html
    my $bpf_prog = substr(
        $self->{reader}->{raw_elf_data},
        $bpf_section->{sh_offset},
        $bpf_section->{sh_size}
    );
    my $license = substr(
        $self->{reader}->{raw_elf_data},
        $license_section->{sh_offset},
        $license_section->{sh_size}
    );

    my $bpf_attrs = {
        prog_type    => BPF_PROG_TYPE_KPROBE,
        insn_cnt     => length($bpf_prog) / 8,
        insns        => $bpf_prog,
        license      => $license,
        log_level    => 3,
        log_size     => 4096 * 16,
        log_buf      => "\0" x ( 4096 * 16 ),
        kern_version => 0,
        prog_flags   => 0,
    };

    return $self->load_bpf_program($bpf_attrs);
}

sub load_bpf_program {
    my ( $self, $bpf_attrs ) = @_;

    my $defaults = {
        prog_type    => 0,
        insn_cnt     => 0,
        insns        => "",
        license      => "",
        log_level    => 1,
        log_size     => 1024 * 10,
        log_buf      => "\0" x ( 1024 * 10 ),
        kern_version => 0,
        prog_flags   => 0,
    };
    my $attrs = { %$defaults, %$bpf_attrs, };

    # bpf_attr構造体のパック
    my $attr = pack(
        "L L Q Q L L Q L L",
        $attrs->{prog_type},
        $attrs->{insn_cnt},
        unpack( "Q", pack( "P", $attrs->{insns} ) ),
        unpack( "Q", pack( "P", $attrs->{license} ) ),
        $attrs->{log_level},
        $attrs->{log_size},
        unpack( "Q", pack( "P", $attrs->{log_buf} ) ),
        $attrs->{kern_version},
        $attrs->{prog_flags}
    );

    # syscallの実行
    my $fd = syscall( sys::ebpf::syscall::SYS_bpf(),
        BPF_PROG_LOAD, $attr, length($attr) );

    if ( $fd < 0 ) {
        my $errno = $!;
        warn "Errno: $errno\n";
        if ( $errno == EACCES || $errno == EPERM ) {
            warn "Permission denied. Are you running as root?\n";
        }
        warn "Log buffer content:\n", $attrs->{log_buf}, "\n";
        die "BPF program load failed: $!\n";
    }
    print "BPF program loaded successfully with FD: $fd\n";

    return $fd;
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
    my ( $self, $prob_section, $reloc_sections, $elf, $map_data ) = @_;
    my $symbols_section = $elf->{symbols};
    for my $reloc_section (@$reloc_sections) {
        my $r_info = $reloc_section->{r_info};
        my $r_offset
            = $reloc_section->{r_offset} + $prob_section->{sh_offset};

        my $sym_index  = $r_info >> 32;           # シンボルインデックスを取得
        my $reloc_type = $r_info & 0xFFFFFFFF;    # リロケーションタイプを取得

        # シンボルテーブルからrelocation対象になり得るシンボル名を取得
        my $symbol
            = find_symbol_table_from_idx( $symbols_section, $sym_index );
        if ( !$symbol ) {
            print "Symbol not found for index: $sym_index\n";
            next;
        }
        my $sym_name = $symbol->{st_name};
        if ( $symbol->{st_shndx} == 0 ) {
            print "Symbol not found for index: $sym_index\n";
            next;
        }

        # `$map_data` の中のタプルを確認して、期待してるマップ名が存在するかチェック(fdを取得)
        my $map_fd = undef;
        for my $tuple (@$map_data) {
            my ( $map_name, $map ) = @$tuple;
            if ( $sym_name eq $map_name ) {
                $map_fd = $map->{map_fd};
                last;    # マップが見つかったらループを抜ける
            }
        }

        if ( defined $map_fd ) {

            # # 指定されたオフセット位置にある `lddw` 命令（16バイト）を取得
            my $bpf_insn
                = substr( $self->{reader}->{raw_elf_data}, $r_offset, 16 )
                ;    # 16バイトを取得
            my $bpf_insn_len = length($bpf_insn);
            print "Before relocation (offset $r_offset): "
                . unpack( 'H*', $bpf_insn )
                . "\n";    # デバッグ出力

            my ( $high, $low )
                = sys::ebpf::asm::deserialize_128bit_instruction($bpf_insn);

            # 即値 (64ビット) にマップFDを設定
            $high->set_imm($map_fd);
            $low->set_imm( $map_fd >> 32 );

            # src_reg に PSEUDO_MAP_FD (1) を設定
            $high->set_src_reg(1);

            # 修正後の命令をパックして、元の場所に書き戻す
            my $new_bpf_insn
                = sys::ebpf::asm::serialize_128bit_instruction( $high, $low );
            substr( $self->{reader}->{raw_elf_data},
                $r_offset, 16, $new_bpf_insn );

            # 書き換えた後の命令を出力
            my $after_bpf_insn
                = substr( $self->{reader}->{raw_elf_data}, $r_offset, 16 );
            print "After relocation (offset $r_offset): "
                . unpack( 'H*', $after_bpf_insn )
                . "\n";    # デバッグ出力
        }
        else {
            print "No matching map found for symbol: $sym_name\n";
        }
    }
}

# BPF プログラムとマップをロード
# args:
#   section_name: BPF プログラムのセクション名
# return:
#   map_collection: マップ名とFDの組になったhashのリファレンス
#   prog_fd: プログラムFD
sub load_bpf {
    my ( $self, $section_name ) = @_;
    my $bpfelf = $self->{bpfelf};
    my $maps   = $self->extract_bpf_map_attributes('maps');

    my @map_collection;

    # map_attr_refの各キー（マップ名）に対して処理を実行
    for my $map (@$maps) {
        my $map_name     = $map->{map_name};
        my $map_instance = sys::ebpf::map->create($map);
        my $map_fd       = $map_instance->{map_fd};
        if ( $map_fd < 0 ) {
            die "Failed to load BPF map: $map_name (FD: $map_fd})\n";
        }
        push @map_collection, [ $map_name, $map_instance ];
    }

    # リロケーションを適用
    print ".rel" . $section_name . "\n";
    my $reloc_section = $bpfelf->{relocations}{ ".rel" . $section_name };
    my $prob_section
        = find_symbol_table_from_name( $bpfelf->{sections}, $section_name );
    if ( defined $reloc_section ) {
        $self->apply_map_relocations( $prob_section, $reloc_section, $bpfelf,
            \@map_collection );
    }

    # todo: bpfprobが複数あるケースにも対応する
    # BPF プログラムをロード
    my $prog_fd = $self->load_bpf_program_from_elf($section_name);

    return ( \@map_collection, $prog_fd );
}

1;
