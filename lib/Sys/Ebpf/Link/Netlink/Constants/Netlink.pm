package Sys::Ebpf::Link::Netlink::Constants::Netlink;

use strict;
use warnings;
use utf8;

use Exporter 'import';

# cf. https://github.com/torvalds/linux/blob/master/tools/include/uapi/linux/netlink.h
my %constants = (
    'NETLINK_ROUTE'          => 0,
    'NETLINK_UNUSED'         => 1,
    'NETLINK_USERSOCK'       => 2,
    'NETLINK_FIREWALL'       => 3,
    'NETLINK_SOCK_DIAG'      => 4,
    'NETLINK_NFLOG'          => 5,
    'NETLINK_XFRM'           => 6,
    'NETLINK_SELINUX'        => 7,
    'NETLINK_ISCSI'          => 8,
    'NETLINK_AUDIT'          => 9,
    'NETLINK_FIB_LOOKUP'     => 10,
    'NETLINK_CONNECTOR'      => 11,
    'NETLINK_NETFILTER'      => 12,
    'NETLINK_IP6_FW'         => 13,
    'NETLINK_DNRTMSG'        => 14,
    'NETLINK_KOBJECT_UEVENT' => 15,
    'NETLINK_GENERIC'        => 16,
    'NETLINK_SCSITRANSPORT'  => 18,
    'NETLINK_ECRYPTFS'       => 19,
    'NETLINK_RDMA'           => 20,
    'NETLINK_CRYPTO'         => 21,
    'NETLINK_SMC'            => 22,

    'NLMSG_NOOP'    => 1,
    'NLMSG_ERROR'   => 2,
    'NLMSG_DONE'    => 3,
    'NLMSG_OVERRUN' => 4,

    # /* Flags values */
    'NLM_F_REQUEST'       => 0x01,
    'NLM_F_MULTI'         => 0x02,
    'NLM_F_ACK'           => 0x04,
    'NLM_F_ECHO'          => 0x08,
    'NLM_F_DUMP_INTR'     => 0x10,
    'NLM_F_DUMP_FILTERED' => 0x20,

    # /* Modifiers to GET request */
    'NLM_F_ROOT'   => 0x100,
    'NLM_F_MATCH'  => 0x200,
    'NLM_F_ATOMIC' => 0x400,

    # 'NLM_F_DUMP'         => ( NLM_F_ROOT | NLM_F_MATCH ),

    # /* Modifiers to NEW request */
    'NLM_F_REPLACE' => 0x100,
    'NLM_F_EXCL'    => 0x200,
    'NLM_F_CREATE'  => 0x400,
    'NLM_F_APPEND'  => 0x800,

    # /* Modifiers to DELETE request */
    'NLM_F_NONREC' => 0x100,

    # /* Flags for ACK message */
    'NLM_F_CAPPED'   => 0x100,
    'NLM_F_ACK_TLVS' => 0x200,

    # /* Attribute types */
    'NLA_F_NESTED'        => ( 1 << 15 ),
    'NLA_F_NET_BYTEORDER' => ( 1 << 14 ),
    'NLMSG_HDRLEN'        => 16,
    'NLA_HDRLEN'          => 4,

    # Socket options
    'NETLINK_ADD_MEMBERSHIP'  => 1,
    'NETLINK_DROP_MEMBERSHIP' => 2,
    'NETLINK_PKTINFO'         => 3,
    'NETLINK_BROADCAST_ERROR' => 4,
    'NETLINK_NO_ENOBUFS'      => 5,
    'NETLINK_RX_RING'         => 6,
    'NETLINK_TX_RING'         => 7,
    'NETLINK_LISTEN_ALL_NSID' => 8,
    'NETLINK_CAP_ACK'         => 10,
    'NETLINK_EXT_ACK'         => 11,
    'NETLINK_GET_STRICT_CHK'  => 12,
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
