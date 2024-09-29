package Sys::Ebpf::Link::Netlink::Constants::Rtnetlink;

use strict;
use warnings;
use utf8;

use Exporter 'import';

# cf. https://github.com/torvalds/linux/blob/master/include/uapi/linux/rtnetlink.h
my %constants = (

    # /* Routing table identifiers. */
    # /* Types of messages */
    'RTM_BASE'             => 16,
    'RTM_NEWLINK'          => 16,
    'RTM_DELLINK'          => 17,
    'RTM_GETLINK'          => 18,
    'RTM_SETLINK'          => 19,
    'RTM_NEWADDR'          => 20,
    'RTM_DELADDR'          => 21,
    'RTM_GETADDR'          => 22,
    'RTM_NEWROUTE'         => 24,
    'RTM_DELROUTE'         => 25,
    'RTM_GETROUTE'         => 26,
    'RTM_NEWNEIGH'         => 28,
    'RTM_DELNEIGH'         => 29,
    'RTM_GETNEIGH'         => 30,
    'RTM_NEWRULE'          => 32,
    'RTM_DELRULE'          => 33,
    'RTM_GETRULE'          => 34,
    'RTM_NEWQDISC'         => 36,
    'RTM_DELQDISC'         => 37,
    'RTM_GETQDISC'         => 38,
    'RTM_NEWTCLASS'        => 40,
    'RTM_DELTCLASS'        => 41,
    'RTM_GETTCLASS'        => 42,
    'RTM_NEWTFILTER'       => 44,
    'RTM_DELTFILTER'       => 45,
    'RTM_GETTFILTER'       => 46,
    'RTM_NEWACTION'        => 48,
    'RTM_DELACTION'        => 49,
    'RTM_GETACTION'        => 50,
    'RTM_NEWPREFIX'        => 52,
    'RTM_GETMULTICAST'     => 58,
    'RTM_GETANYCAST'       => 62,
    'RTM_NEWNEIGHTBL'      => 64,
    'RTM_GETNEIGHTBL'      => 66,
    'RTM_SETNEIGHTBL'      => 67,
    'RTM_NEWNDUSEROPT'     => 68,
    'RTM_NEWADDRLABEL'     => 72,
    'RTM_DELADDRLABEL'     => 73,
    'RTM_GETADDRLABEL'     => 74,
    'RTM_GETDCB'           => 78,
    'RTM_SETDCB'           => 79,
    'RTM_NEWNETCONF'       => 80,
    'RTM_GETNETCONF'       => 82,
    'RTM_NEWMDB'           => 84,
    'RTM_DELMDB'           => 85,
    'RTM_GETMDB'           => 86,
    'RTM_NEWNSID'          => 88,
    'RTM_DELNSID'          => 89,
    'RTM_GETNSID'          => 90,
    'RTM_NEWSTATS'         => 92,
    'RTM_GETSTATS'         => 94,
    'RTM_NEWCACHEREPORT'   => 96,
    'RTM_NEWCHAIN'         => 100,
    'RTM_DELCHAIN'         => 101,
    'RTM_GETCHAIN'         => 102,
    'RTM_NEWNEXTHOP'       => 104,
    'RTM_DELNEXTHOP'       => 105,
    'RTM_GETNEXTHOP'       => 106,
    'RTM_NEWLINKPROP'      => 108,
    'RTM_DELLINKPROP'      => 109,
    'RTM_GETLINKPROP'      => 110,
    'RTM_NEWVLAN'          => 112,
    'RTM_DELVLAN'          => 113,
    'RTM_GETVLAN'          => 114,
    'RTM_NEWNEXTHOPBUCKET' => 116,
    'RTM_DELNEXTHOPBUCKET' => 117,
    'RTM_GETNEXTHOPBUCKET' => 118,
    'RTM_NEWTUNNEL'        => 120,
    'RTM_DELTUNNEL'        => 121,
    'RTM_GETTUNNEL'        => 122,
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
