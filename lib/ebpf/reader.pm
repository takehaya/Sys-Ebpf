package ebpf::reader;

use strict;
use warnings;
use utf8;

our $VERSION = $ebpf::VERSION;

use ebpf::elf::parser ();

# cf. https://www.ietf.org/archive/id/draft-thaler-bpf-elf-00.html
sub new {
    my ( $class, $file ) = @_;
    my $self = { file => $file };
    bless $self, $class;
    return $self;
}

# ebpf binaryを読み出して、elfをパースする
sub parse_ebpf {
    my ($self) = @_;
    my $data = read_file( $self->{file} );
    $self->{raw_elf_data} = $data;
    my $elfloader = ebpf::elf::parser->new($data);
    my $elf       = $elfloader->parse_elf();

    # BPF Type only validate
    if ( !$elfloader->is_bpf_machine_type( $elf->{e_machine} ) ) {
        die "Invalid ELF type: $elf->{e_type}";
    }

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
