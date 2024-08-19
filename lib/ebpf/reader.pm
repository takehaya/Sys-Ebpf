package ebpf::reader;

use strict;
use warnings;

sub new {
    my ($class, $file) = @_;
    my $self = { file => $file };
    bless $self, $class;
    return $self;
}


# ebpf binaryを読み出して、elfをパースする
sub parse_ebpf {
    my ($self) = @_;
    my $file = $self->{file};
    my $data = read_file($file);
    my $elf = parse_elf($data);
    return $elf;
}

# ファイルを読み出す
sub read_file {
    my ($file) = @_;
    open my $fh, '<', $file or die "Can't open $file: $!";
    binmode $fh;
    my $data;
    {
        local $/;
        $data = <$fh>;
    }
    close $fh;
    return $data;
}

# elfをパースする
sub parse_elf {
    my ($data) = @_;
    my $elf = {};
    my ($magic, $class, $endian, $version, $abi, $abi_version, $pad) = unpack('A4C2A5C3', substr($data, 0, 16));
    $elf->{magic} = $magic;
    $elf->{class} = $class;
    $elf->{endian} = $endian;
    $elf->{version} = $version;
    $elf->{abi} = $abi;
    $elf->{abi_version} = $abi_version;
    $elf->{pad} = $pad;
    return $elf;
}

1;