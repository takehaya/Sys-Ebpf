package Sys::Ebpf::Link::Netlink::Constants::Iflink;

use strict;
use warnings;
use utf8;

use Exporter 'import';

# cf. https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_link.h
my %constants = (

    # IFLA_AF_SPEC section
    'IFLA_UNSPEC' => 0,
    'IFLA_XDP'    => 43,

    # /* XDP section */
    'XDP_FLAGS_UPDATE_IF_NOEXIST' => 1 << 0,
    'XDP_FLAGS_SKB_MODE'          => 1 << 1,
    'XDP_FLAGS_DRV_MODE'          => 1 << 2,
    'XDP_FLAGS_HW_MODE'           => 1 << 3,
    'XDP_FLAGS_REPLACE'           => 1 << 4,
    'XDP_FLAGS_MODES'             => ( 1 << 1 | 1 << 2 | 1 << 3 ),
    'XDP_FLAGS_MASK'       => ( 1 << 0 | 1 << 1 | 1 << 2 | 1 << 3 | 1 << 4 ),
    'XDP_ATTACHED_NONE'    => 0,
    'XDP_ATTACHED_DRV'     => 1,
    'XDP_ATTACHED_SKB'     => 2,
    'XDP_ATTACHED_HW'      => 3,
    'XDP_ATTACHED_MULTI'   => 4,
    'IFLA_XDP_UNSPEC'      => 0,
    'IFLA_XDP_FD'          => 1,
    'IFLA_XDP_ATTACHED'    => 2,
    'IFLA_XDP_FLAGS'       => 3,
    'IFLA_XDP_PROG_ID'     => 4,
    'IFLA_XDP_DRV_PROG_ID' => 5,
    'IFLA_XDP_SKB_PROG_ID' => 6,
    'IFLA_XDP_HW_PROG_ID'  => 7,
    'IFLA_XDP_EXPECTED_FD' => 8,
);

# Export all constants
our @EXPORT_OK   = keys %constants;
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

# Define constants as subroutines
for my $name (@EXPORT_OK) {
    no strict 'refs';
    *{$name} = sub () { $constants{$name} };
}

1;
