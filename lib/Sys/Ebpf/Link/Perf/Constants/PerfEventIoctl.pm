package Sys::Ebpf::Link::Perf::Constants::PerfEventIoctl;

use strict;
use warnings;
use utf8;

use Exporter 'import';

# Direction Bits
use constant {
    _IOC_NONE  => 0,
    _IOC_WRITE => 1,
    _IOC_READ  => 2,
};

# Shift Values and Masks
use constant {
    _IOC_NRBITS   => 8,
    _IOC_TYPEBITS => 8,
    _IOC_SIZEBITS => 14,
    _IOC_DIRBITS  => 2,

    _IOC_NRSHIFT   => 0,
    _IOC_TYPESHIFT => 8,
    _IOC_SIZESHIFT => 16,
    _IOC_DIRSHIFT  => 30,
};

# Size Constants
use constant {
    SIZE_U64                  => 8,
    SIZE_U32                  => 4,
    SIZE_CHAR_PTR             => 8,
    SIZE_PERF_EVENT_QUERY_BPF => 32,
    SIZE_PERF_EVENT_ATTR      => 112,    # Updated size
};

# Wrapper function for left shift operation
sub _left_shift {
    my ( $value, $shift ) = @_;
    return $value << $shift;
}

# Helper Functions
sub _IOC {
    my ( $dir, $type, $nr, $size ) = @_;
    return ( _left_shift( $dir, _IOC_DIRSHIFT )
            | _left_shift( $type, _IOC_TYPESHIFT )
            | _left_shift( $nr,   _IOC_NRSHIFT )
            | _left_shift( $size, _IOC_SIZESHIFT ) );
}

sub _IO   { _IOC( _IOC_NONE,              $_[0], $_[1], 0 ) }
sub _IOR  { _IOC( _IOC_READ,              $_[0], $_[1], $_[2] ) }
sub _IOW  { _IOC( _IOC_WRITE,             $_[0], $_[1], $_[2] ) }
sub _IOWR { _IOC( _IOC_READ | _IOC_WRITE, $_[0], $_[1], $_[2] ) }

# Ioctl Constants
my %constants = (
    PERF_EVENT_IOC_ENABLE       => _IO( ord('$'), 0 ),
    PERF_EVENT_IOC_DISABLE      => _IO( ord('$'), 1 ),
    PERF_EVENT_IOC_REFRESH      => _IO( ord('$'), 2 ),
    PERF_EVENT_IOC_RESET        => _IO( ord('$'), 3 ),
    PERF_EVENT_IOC_PERIOD       => _IOW( ord('$'), 4, SIZE_U64 ),
    PERF_EVENT_IOC_SET_OUTPUT   => _IO( ord('$'), 5 ),
    PERF_EVENT_IOC_SET_FILTER   => _IOW( ord('$'), 6, SIZE_CHAR_PTR ),
    PERF_EVENT_IOC_ID           => _IOR( ord('$'), 7, SIZE_U64 ),
    PERF_EVENT_IOC_SET_BPF      => _IOW( ord('$'), 8, SIZE_U32 ),
    PERF_EVENT_IOC_PAUSE_OUTPUT => _IOW( ord('$'), 9, SIZE_U32 ),
    PERF_EVENT_IOC_QUERY_BPF    =>
        _IOWR( ord('$'), 10, SIZE_PERF_EVENT_QUERY_BPF ),
    PERF_EVENT_IOC_MODIFY_ATTRIBUTES =>
        _IOW( ord('$'), 11, SIZE_PERF_EVENT_ATTR ),
);

# Automatically populate @EXPORT_OK with all constants
our @EXPORT_OK   = keys %constants;
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

# Export Constants
for my $name (@EXPORT_OK) {
    no strict 'refs';
    *{$name} = sub () { hex( sprintf( "0x%08X", $constants{$name} ) ) };
}

# # Debug: Print all constants
# for my $name ( sort keys %constants ) {
#     printf( "%-30s => 0x%08X\n", $name, $constants{$name} );
# }

1;
