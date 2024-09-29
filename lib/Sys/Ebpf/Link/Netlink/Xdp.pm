package Sys::Ebpf::Link::Netlink::Xdp;

use strict;
use warnings;

use IO::Interface::Simple ();
use Socket                qw( AF_UNSPEC );
use Errno                 ();
use Carp                  qw( croak );
use Try::Tiny             qw( catch finally try );

use Sys::Ebpf::Link::Netlink::Socket qw(
    pack_nlattr
    pack_nlmsghdr
    pack_ifinfomsg
);
use Sys::Ebpf::Link::Netlink::Constants::Iflink qw(
    IFLA_XDP
    IFLA_XDP_FD
    IFLA_XDP_FLAGS
    XDP_FLAGS_UPDATE_IF_NOEXIST
    XDP_FLAGS_DRV_MODE
);
use Sys::Ebpf::Link::Netlink::Constants::Netlink qw(
    NLA_F_NESTED
    NLM_F_REQUEST
    NLM_F_ACK
    NLMSG_HDRLEN
    NLA_HDRLEN
    NETLINK_ROUTE
    NLMSG_ERROR
    NETLINK_EXT_ACK
);
use Sys::Ebpf::Link::Netlink::Constants::Rtnetlink qw(RTM_SETLINK);

use Data::HexDump ();

sub _send_and_recv_netlink_message {
    my ( $nlmsg, $nlmsg_seq ) = @_;
    my $netlink
        = Sys::Ebpf::Link::Netlink::Socket->new( Proto => NETLINK_ROUTE );
    try {
        $netlink->send_message($nlmsg);

        my $response = $netlink->receive_message();
        _handle_response( $response, $nlmsg_seq );
    }
    catch {
        my $error = $_;
        croak $error;
    }
    finally {
        $netlink->close();
    };
}

sub _handle_response {
    my ( $response, $nlmsg_seq ) = @_;

    my $received_bytes = length($response);

    if ( $received_bytes >= NLMSG_HDRLEN ) {
        my ( $len, $type, $flags, $seq, $pid )
            = unpack( 'I S S I I', substr( $response, 0, NLMSG_HDRLEN ) );
        if ( $seq != $nlmsg_seq ) {
            croak "Netlink response sequence number does not match request";
        }
        if ( $type == NLMSG_ERROR ) {
            my $error_code
                = unpack( 'i', substr( $response, NLMSG_HDRLEN, 4 ) );
            if ( $error_code != 0 ) {
                my $error_msg
                    = Sys::Ebpf::Link::Netlink::get_error_message($response);
                croak "Netlink error: $error_code ($error_msg)";
            }
        }
    }
    else {
        croak "Received Netlink response is too short";
    }
}

sub _create_nlmsg {
    my ( $ifindex, $prog_fd, $flags ) = @_;

    my $ifinfomsg = pack( 'C C S L L L', AF_UNSPEC, 0, 0, $ifindex, 0, 0 );
    my $nla_fd    = pack_nlattr( IFLA_XDP_FD,    pack( 'i', $prog_fd ) );
    my $nla_flags = pack_nlattr( IFLA_XDP_FLAGS, pack( 'I', $flags ) );
    my $xdp_attrs = $nla_fd . $nla_flags;
    my $nla_xdp   = pack_nlattr( NLA_F_NESTED | IFLA_XDP, $xdp_attrs );

    my $req       = $ifinfomsg . $nla_xdp;
    my $nlmsg_len = NLMSG_HDRLEN + length($req);
    my $nlmsg_seq = int( rand(0xFFFFFFFF) );

    my $nlmsg
        = pack_nlmsghdr( $nlmsg_len, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK,
        $nlmsg_seq, $$, )
        . $req;

    return {
        nlmsg     => $nlmsg,
        nlmsg_seq => $nlmsg_seq,
    };
}

sub attach_xdp {
    my ( $prog_fd, $ifname, $flags ) = @_;

    # インターフェースのインデックスを取得
    my $iface = IO::Interface::Simple->new($ifname);
    unless ($iface) {
        croak "Interface $ifname not found";
    }
    my $ifindex = $iface->index;

    $flags //= XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;

    my $nlmsg = _create_nlmsg( $ifindex, $prog_fd, $flags );

    _send_and_recv_netlink_message( $nlmsg->{nlmsg}, $nlmsg->{nlmsg_seq} );

    return {
        prog_fd => $prog_fd,
        ifindex => $ifindex,
        ifname  => $ifname,
        flags   => $flags,
    };
}

sub detach_xdp {
    my ( $ifname, $flags ) = @_;
    my $iface = IO::Interface::Simple->new($ifname);
    unless ($iface) {
        croak "Interface $ifname not found";
    }
    my $ifindex = $iface->index;

    $flags //= XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;

    my $nlmsg = _create_nlmsg( $ifindex, -1, $flags );

    _send_and_recv_netlink_message( $nlmsg->{nlmsg}, $nlmsg->{nlmsg_seq} );
}

1;
