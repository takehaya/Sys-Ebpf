package ebpf::reader;

use strict;
use warnings;

use ebpf::elf;

sub new {
    my ($class, $file) = @_;
    my $self = { file => $file };
    bless $self, $class;
    return $self;
}


# ebpf binaryを読み出して、elfをパースする
sub parse_ebpf {
    my ($self) = @_;
    my $data = read_file($self->{file});
    my $elfloader = ebpf::elf->new($data);
    my $elf = $elfloader->parse_elf();
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

1;