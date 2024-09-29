package Sys::Ebpf::Link::Netlink::Xdp;

use strict;
use warnings;
use IO::Interface::Simple ();
use Sys::Ebpf::Link::Netlink::Socket
    qw(pack_nlattr pack_nlmsghdr pack_ifinfomsg);
use Sys::Ebpf::Link::Netlink::Constants::Iflink qw(
    IFLA_XDP
    IFLA_XDP_FD
    IFLA_XDP_ATTACHED
    IFLA_XDP_FLAGS
    XDP_FLAGS_UPDATE_IF_NOEXIST
    XDP_FLAGS_SKB_MODE
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
);

use Socket qw( AF_UNSPEC );
use Errno  ();

# 定数の定義
use constant {
    RTM_SETLINK => 19,
    IFF_UP      => 1 << 0,
};

# ヘルパー関数をインポート
use Sys::Ebpf::Link::Netlink::Socket
    qw(pack_nlattr pack_nlmsghdr pack_ifinfomsg);

sub attach_xdp {
    my ( $prog_fd, $ifname ) = @_;

    print "Entering attach_xdp\n";

    # インターフェースのインデックスを取得
    my $iface = IO::Interface::Simple->new($ifname);
    unless ($iface) {
        die "Interface $ifname not found";
    }
    my $ifindex = $iface->index;
    print "Interface name: $ifname, index: $ifindex\n";

    # フラグを設定（XDP_FLAGS_SKB_MODEを外す）
    my $flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
    print "XDP flags: $flags\n";

    # Netlinkメッセージの構築
    # ifinfomsgをパック
    my $ifinfomsg = pack_ifinfomsg( AF_UNSPEC, 0, $ifindex, 0, 0 );

    # 属性をパック
    my $nla_fd    = pack_nlattr( IFLA_XDP_FD,    pack( 'i', $prog_fd ) );
    my $nla_flags = pack_nlattr( IFLA_XDP_FLAGS, pack( 'I', $flags ) );
    my $xdp_attrs = $nla_fd . $nla_flags;
    my $nla_xdp   = pack_nlattr( NLA_F_NESTED | IFLA_XDP, $xdp_attrs );

    # 全体のメッセージを構築
    my $req       = $ifinfomsg . $nla_xdp;
    my $nlmsg_len = NLMSG_HDRLEN + length($req);
    my $nlmsg_seq = int( rand(0xFFFFFFFF) );
    my $nlmsg
        = pack_nlmsghdr( $nlmsg_len, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK,
        $nlmsg_seq, $$ )
        . $req;

    # Netlinkメッセージのダンプ（デバッグ用）
    use Data::HexDump ();
    print "Netlink message hex dump:\n";
    print Data::HexDump::HexDump($nlmsg);

    # Netlinkソケットを作成してメッセージを送信
    my $netlink
        = Sys::Ebpf::Link::Netlink::Socket->new( Proto => NETLINK_ROUTE );
    $netlink->send_message($nlmsg);
    print "Netlink message sent successfully\n";

    # 応答を受信
    my $response       = $netlink->receive_message();
    my $received_bytes = length($response);
    print "Received Netlink response, bytes received: $received_bytes\n";

    # エラーチェック
    if ( $received_bytes >= NLMSG_HDRLEN ) {
        my ( $len, $type, $flags, $seq, $pid )
            = unpack( 'I S S I I', substr( $response, 0, NLMSG_HDRLEN ) );
        print
            "Netlink response header: len=$len, type=$type, flags=$flags, seq=$seq, pid=$pid\n";
        if ( $seq != $nlmsg_seq ) {
            die "Netlink response sequence number does not match request";
        }
        if ( $type == NLMSG_ERROR ) {
            my $error_code
                = unpack( 'i', substr( $response, NLMSG_HDRLEN, 4 ) );
            print "Netlink error code: $error_code\n";
            if ( $error_code != 0 ) {

                # 拡張エラーメッセージを取得
                my $error_msg = get_netlink_error_msg($response);
                die "Netlink error: $error_code ("
                    . $error_code
                    . ") $error_msg";
            }
            else {
                print "Netlink response indicates success\n";
            }
        }
        else {
            print "Netlink response type: $type\n";
        }
    }
    else {
        print "Received Netlink response is too short\n";
    }

    $netlink->close();
    print "Exiting attach_xdp\n";

    return {
        prog_fd => $prog_fd,
        ifindex => $ifindex,
        ifname  => $ifname,
        flags   => $flags,
    };
}

# 拡張エラーメッセージを取得する関数
sub get_netlink_error_msg {
    my ($response) = @_;
    my $offset     = NLMSG_HDRLEN + 4;    # After the error code
    my $len        = length($response);
    if ( $len > $offset ) {
        my $attr_data = substr( $response, $offset );
        while ( length($attr_data) >= NLA_HDRLEN ) {
            my ( $nla_len, $nla_type ) = unpack( "S S", $attr_data );
            my $payload
                = substr( $attr_data, NLA_HDRLEN, $nla_len - NLA_HDRLEN );
            if ( $nla_type == 1 ) {    # NLMSGERR_ATTR_MSG
                return unpack( "Z*", $payload );
            }
            $attr_data = substr( $attr_data, ( $nla_len + 3 ) & ~3 )
                ;                      # Align to 4 bytes
        }
    }
    return "";
}

sub detach_xdp {
    my ($ifname) = @_;

    print "Entering detach_xdp\n";
    my $iface = IO::Interface::Simple->new($ifname);
    unless ($iface) {
        die "Interface $ifname not found";
    }
    my $ifindex = $iface->index;

    print "Detaching XDP from interface: $ifname (index: $ifindex)\n";

    # Netlinkメッセージの構築
    # ifinfomsgをパック
    my $ifinfomsg = pack_ifinfomsg( AF_UNSPEC, 0, $ifindex, 0, 0 );

    # 属性をパック
    my $prog_fd   = -1;
    my $nla_fd    = pack_nlattr( IFLA_XDP_FD, pack( 'i', $prog_fd ) );
    my $flags     = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
    my $nla_flags = pack_nlattr( IFLA_XDP_FLAGS, pack( 'I', $flags ) );
    my $xdp_attrs = $nla_fd . $nla_flags;
    my $nla_xdp   = pack_nlattr( NLA_F_NESTED | IFLA_XDP, $xdp_attrs );

    # 全体のメッセージを構築
    my $req       = $ifinfomsg . $nla_xdp;
    my $nlmsg_len = NLMSG_HDRLEN + length($req);
    my $nlmsg
        = pack_nlmsghdr( $nlmsg_len, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK,
        0, $$ )
        . $req;

    # Netlinkソケットを作成してメッセージを送信
    my $netlink
        = Sys::Ebpf::Link::Netlink::Socket->new( Proto => NETLINK_ROUTE );
    $netlink->send_message($nlmsg);
    print "Netlink message sent successfully\n";

    # 応答を受信
    my $response       = $netlink->receive_message();
    my $received_bytes = length($response);
    print "Received Netlink response, bytes received: $received_bytes\n";

    # エラーチェック
    if ( $received_bytes >= NLMSG_HDRLEN ) {
        my ( $len, $type, $flags, $seq, $pid )
            = unpack( 'I S S I I', substr( $response, 0, NLMSG_HDRLEN ) );
        print
            "Netlink response header: len=$len, type=$type, flags=$flags, seq=$seq, pid=$pid\n";
        if ( $type == NLMSG_ERROR ) {
            my $error_code
                = unpack( 'i', substr( $response, NLMSG_HDRLEN, 4 ) );
            print "Netlink error code: $error_code\n";
            if ( $error_code != 0 ) {
                die "Netlink error during detach: $error_code ("
                    . strerror( -$error_code ) . ")";
            }
            else {
                print "Netlink response indicates success\n";
            }
        }
        else {
            print "Netlink response type: $type\n";
        }
    }
    else {
        print "Received Netlink response is too short\n";
    }

    $netlink->close();
    print "Exiting detach_xdp\n";
}

1;
