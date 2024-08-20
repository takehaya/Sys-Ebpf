package ebpf::elf;

use strict;
use warnings;

# ebpf binaryを読み出して、elfをパースします
# コンストラクタにはファイルのバイナリデータが渡されます
sub new {
    my ($class, $data) = @_;
    my $self = { data => $data };
    bless $self, $class;
    return $self;
}

# ELFヘッダをパースする
sub parse_elf {
    my ($self) = @_;
    my $elf = {};

    my $data = $self->{data};
    # ELFヘッダをパース
    my ($magic, $class, $endian, $version, $abi, $abi_version) = unpack('A4C3A5C2', substr($data, 0, 16));
    $elf->{magic} = $magic;
    $elf->{class} = $class == 1 ? 'ELF32' : 'ELF64';
    $elf->{endian} = $endian == 1 ? 'little endian' : 'big endian';
    $elf->{version} = $version;
    $elf->{abi} = $abi;
    $elf->{abi_version} = $abi_version;

    # ELFファイルのサイズなどを取得
    my ($e_type, $e_machine, $e_version, $e_entry, $e_phoff, $e_shoff, $e_flags, $e_ehsize, $e_phentsize,
        $e_phnum, $e_shentsize, $e_shnum, $e_shstrndx) = unpack('S S L Q Q Q L S S S S S S', substr($data, 16, 48));

    $elf->{e_type} = $e_type;
    $elf->{e_machine} = $e_machine;
    $elf->{e_version} = $e_version;
    $elf->{e_entry} = $e_entry;
    $elf->{e_phoff} = $e_phoff;
    $elf->{e_shoff} = $e_shoff;
    $elf->{e_flags} = $e_flags;
    $elf->{e_ehsize} = $e_ehsize;
    $elf->{e_phentsize} = $e_phentsize;
    $elf->{e_phnum} = $e_phnum;
    $elf->{e_shentsize} = $e_shentsize;
    $elf->{e_shnum} = $e_shnum;
    $elf->{e_shstrndx} = $e_shstrndx;

    # セクションヘッダとシンボルテーブルをパースするための追加処理
    $elf->{sections} = parse_sections($data, $elf->{e_shoff}, $elf->{e_shnum}, $elf->{e_shentsize});
    $elf->{symbols} = parse_symbols($data, $elf->{sections}, $elf->{e_shstrndx});

    return $elf;
}

# セクションヘッダをパースする
sub parse_sections {
    my ($data, $shoff, $shnum, $shentsize) = @_;
    my @sections;

    for my $i (0 .. $shnum - 1) {
        my $offset = $shoff + $i * $shentsize;
        my ($sh_name, $sh_type, $sh_flags, $sh_addr, $sh_offset, $sh_size, $sh_link, $sh_info, $sh_addralign, $sh_entsize) =
            unpack('L L Q Q Q Q L L Q Q', substr($data, $offset, $shentsize));

        push @sections, {
            sh_name => $sh_name,
            sh_type => $sh_type,
            sh_flags => $sh_flags,
            sh_addr => $sh_addr,
            sh_offset => $sh_offset,
            sh_size => $sh_size,
            sh_link => $sh_link,
            sh_info => $sh_info,
            sh_addralign => $sh_addralign,
            sh_entsize => $sh_entsize,
        };
    }

    return \@sections;
}

# シンボルテーブルをパースする
sub parse_symbols {
    my ($data, $sections, $strtab_idx) = @_;
    my @symbols;

    my $strtab_section = $sections->[$strtab_idx];
    my $strtab_offset = $strtab_section->{sh_offset};
    my $strtab_size = $strtab_section->{sh_size};

    for my $section (@$sections) {
        next unless $section->{sh_type} == 2; # SYMTAB

        my $num_symbols = $section->{sh_size} / $section->{sh_entsize};
        for my $i (0 .. $num_symbols - 1) {
            my $offset = $section->{sh_offset} + $i * $section->{sh_entsize};
            my ($st_name, $st_info, $st_other, $st_shndx, $st_value, $st_size) =
                unpack('L C C S Q Q', substr($data, $offset, $section->{sh_entsize}));

            my $name_offset = $strtab_offset + $st_name;
            my $name = unpack('Z*', substr($data, $name_offset, $strtab_size - $name_offset));

            push @symbols, {
                st_name => $name,
                st_info => $st_info,
                st_other => $st_other,
                st_shndx => $st_shndx,
                st_value => $st_value,
                st_size => $st_size,
            };
        }
    }

    return \@symbols;
}

1;