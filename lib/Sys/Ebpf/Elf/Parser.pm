package Sys::Ebpf::Elf::Parser;

use strict;
use warnings;
use utf8;

our $VERSION = $Sys::Ebpf::VERSION;

use Sys::Ebpf::Elf::Constants;

use Sys::Ebpf::Elf::MachineType ();

# elf64形式はこの通り
# cf. https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
# $cat /usr/include/elf.h | grep -B16 " Elf64_Ehdr;"
# typedef struct
# {
#   unsigned char e_ident[EI_NIDENT];     /* Magic number and other info */
#   Elf64_Half    e_type;                 /* Object file type */
#   Elf64_Half    e_machine;              /* Architecture */
#   Elf64_Word    e_version;              /* Object file version */
#   Elf64_Addr    e_entry;                /* Entry point virtual address */
#   Elf64_Off     e_phoff;                /* Program header table file offset */
#   Elf64_Off     e_shoff;                /* Section header table file offset */
#   Elf64_Word    e_flags;                /* Processor-specific flags */
#   Elf64_Half    e_ehsize;               /* ELF header size in bytes */
#   Elf64_Half    e_phentsize;            /* Program header table entry size */
#   Elf64_Half    e_phnum;                /* Program header table entry count */
#   Elf64_Half    e_shentsize;            /* Section header table entry size */
#   Elf64_Half    e_shnum;                /* Section header table entry count */
#   Elf64_Half    e_shstrndx;             /* Section header string table index */
# } Elf64_Ehdr;
# typedef uint64_t	Elf64_Addr;
# typedef uint16_t	Elf64_Half;
# typedef uint64_t	Elf64_Off;
# typedef int32_t	Elf64_Sword;
# typedef int64_t	Elf64_Sxword;
# typedef uint32_t	Elf64_Word;
# typedef uint64_t	Elf64_Lword;
# typedef uint64_t	Elf64_Xword;

# ebpf binaryを読み出して、elfをパースします
# コンストラクタにはファイルのバイナリデータが渡されます
sub new {
    my ( $class, $data ) = @_;
    my $self = { data => $data };
    bless $self, $class;
    return $self;
}

# ELFヘッダをパースする
sub parse_elf {
    my ($self) = @_;
    my $elf = {};

    my $data        = $self->{data};
    my $byte_offset = 0;
    my $byte_range  = 16;              # ELFヘッダは16バイト
                                       # e_identをパース
    my ( $magic, $class, $endian, $version, $abi, $abi_version )
        = unpack( 'A4C3A5C2',
        substr( $data, $byte_offset, $byte_offset + $byte_range ) );
    $elf->{magic}       = $magic;
    $elf->{class}       = $class == 1  ? 'ELF32'         : 'ELF64';
    $elf->{endian}      = $endian == 1 ? 'little endian' : 'big endian';
    $elf->{version}     = $version;
    $elf->{abi}         = $abi;
    $elf->{abi_version} = $abi_version;

    $byte_offset += $byte_range;
    $byte_range = 32;

    # ELFファイルのサイズなどを取得
    my ($e_type,      $e_machine, $e_version, $e_entry,     $e_phoff,
        $e_shoff,     $e_flags,   $e_ehsize,  $e_phentsize, $e_phnum,
        $e_shentsize, $e_shnum,   $e_shstrndx
        )
        = unpack( 'S S L Q Q Q L S S S S S S',
        substr( $data, $byte_offset, $byte_offset + $byte_range ) );

    $elf->{e_type}    = $e_type;
    $elf->{e_machine} = $e_machine;
    $elf->{e_machine_name}
        = Sys::Ebpf::Elf::MachineType->get_machine_name($e_machine);
    $elf->{e_version}   = $e_version;
    $elf->{e_entry}     = $e_entry;
    $elf->{e_phoff}     = $e_phoff;
    $elf->{e_shoff}     = $e_shoff;
    $elf->{e_flags}     = $e_flags;
    $elf->{e_ehsize}    = $e_ehsize;
    $elf->{e_phentsize} = $e_phentsize;
    $elf->{e_phnum}     = $e_phnum;
    $elf->{e_shentsize} = $e_shentsize;
    $elf->{e_shnum}     = $e_shnum;
    $elf->{e_shstrndx}  = $e_shstrndx;

    # section tableのセクション名を取得するために文字列テーブルセクションを取得
    my $strtab_section_offset
        = $elf->{e_shoff} + $elf->{e_shstrndx} * $elf->{e_shentsize};
    my $strtab_offset
        = unpack( 'Q', substr( $data, $strtab_section_offset + 24, 8 ) );

    # セクションヘッダとシンボルテーブルをパースするための追加処理
    $elf->{sections}
        = parse_sections( $data, $elf->{e_shoff}, $elf->{e_shnum},
        $elf->{e_shentsize}, $strtab_offset );
    $elf->{symbols}
        = parse_symbols( $data, $elf->{sections}, $elf->{e_shstrndx} );
    $elf->{relocations} = parse_relocations( $data, $elf->{sections} );
    return $elf;
}

# セクションヘッダをパースする
# args
#   data: ELFバイナリデータの文字列
#   shoff: セクションヘッダテーブルのオフセット
#   shnum: セクション数
#   shentsize: セクションヘッダのサイズ
#   strtab_offset: セクション名の文字列テーブルのオフセット
# return
#   sections: セクション情報の配列
sub parse_sections {
    my ( $data, $shoff, $shnum, $shentsize, $strtab_offset ) = @_;
    my @sections;

    for my $i ( 0 .. $shnum - 1 ) {
        my $offset = $shoff + $i * $shentsize;
        my ($sh_name_offset, $sh_type, $sh_flags, $sh_addr,
            $sh_offset,      $sh_size, $sh_link,  $sh_info,
            $sh_addralign,   $sh_entsize
            )
            = unpack( 'L L Q Q Q Q L L Q Q',
            substr( $data, $offset, $shentsize ) );

        # セクション名を取得
        my $name_offset = $strtab_offset + $sh_name_offset;
        my $sh_name     = unpack( 'Z*', substr( $data, $name_offset ) );

        push @sections,
            {
            sh_index     => $i,
            sh_name      => $sh_name,
            sh_type      => $sh_type,
            sh_flags     => $sh_flags,
            sh_addr      => $sh_addr,
            sh_offset    => $sh_offset,
            sh_size      => $sh_size,
            sh_link      => $sh_link,
            sh_info      => $sh_info,
            sh_addralign => $sh_addralign,
            sh_entsize   => $sh_entsize,
            };
    }

    return \@sections;
}

# シンボルテーブルをパースする
# args
#   data: ELFバイナリデータの文字列
#   sections: セクション情報の配列
#   strtab_idx: シンボルテーブルの文字列テーブルのインデックス
# return
#   symbols: シンボルテーブルのハッシュのリファレンス
sub parse_symbols {
    my ( $data, $sections, $strtab_idx ) = @_;
    my @symbols;

    # get string table section
    my $strtab_section = $sections->[$strtab_idx];
    my $strtab_offset  = $strtab_section->{sh_offset};
    my $strtab_size    = $strtab_section->{sh_size};

    # get symbol table section
    my $symtab_section = find_section( $sections, '.symtab' );
    my $num_symbols
        = $symtab_section->{sh_size} / $symtab_section->{sh_entsize};

    for my $i ( 0 .. $num_symbols - 1 ) {
        my $offset = $symtab_section->{sh_offset}
            + $i * $symtab_section->{sh_entsize};
        my ( $st_name, $st_info, $st_other, $st_shndx, $st_value, $st_size )
            = unpack( 'L C C S Q Q',
            substr( $data, $offset, $symtab_section->{sh_entsize} ) );

        my $name_offset = $strtab_offset + $st_name;
        my $name        = unpack(
            'Z*',
            substr(
                $data, $name_offset,
                $strtab_size - ( $name_offset - $strtab_offset )
            )
        );
        my $symbol = {
            st_name  => $name,
            st_info  => $st_info,
            st_other => $st_other,
            st_shndx => $st_shndx,
            st_value => $st_value,
            st_size  => $st_size,
            st_type  => $st_info & 0xf,
            st_bind  => $st_info >> 4,
        };

        push @symbols, $symbol;
    }

    return \@symbols;
}

# リロケーションテーブルをパースする
# args
#   data: ELFバイナリデータの文字列
#   sections: セクション情報の配列
# return
#   relocations: リロケーションテーブルのハッシュのリファレンス
sub parse_relocations {
    my ( $data, $sections ) = @_;
    my %relocations;

    for my $section (@$sections) {
        unless ( $section->{sh_type} == Sys::Ebpf::Elf::Constants::SHT_REL
            || $section->{sh_type} == Sys::Ebpf::Elf::Constants::SHT_RELA )
        {
            next;
        }
        my @relocation;
        my $sh_type         = $section->{sh_type};
        my $num_relocations = $section->{sh_size} / $section->{sh_entsize};

        for my $i ( 0 .. $num_relocations - 1 ) {
            my $offset = $section->{sh_offset} + $i * $section->{sh_entsize};
            my ( $r_offset, $r_info, $r_addend );

            # リロケーションテーブルのエントリをパース
            # 64ビットの場合はQで8バイトを読み込む(TODO: 32ビットの場合はLで4バイトを読み込む)
            if ( $sh_type == Sys::Ebpf::Elf::Constants::SHT_REL ) {
                ( $r_offset, $r_info )
                    = unpack( 'Q<Q<',
                    substr( $data, $offset, $section->{sh_entsize} ) );
                $r_addend = undef;
            }
            else {    # SHT_RELA
                ( $r_offset, $r_info, $r_addend )
                    = unpack( 'Q<Q<Q<',
                    substr( $data, $offset, $section->{sh_entsize} ) );
            }

            push @relocation,
                {
                sh_type  => $sh_type,
                r_offset => $r_offset,
                r_info   => $r_info,
                r_addend => $r_addend,
                };
        }
        $relocations{ $section->{sh_name} } = \@relocation;
    }

    return \%relocations;
}

sub is_bpf_machine_type {
    my ( $self, $e_machine ) = @_;
    return $e_machine == Sys::Ebpf::Elf::Constants::EM_BPF;
}

sub find_section {
    my ( $sections, $name ) = @_;
    return ( grep { $_->{sh_name} eq $name } @$sections )[0];
}

1;
