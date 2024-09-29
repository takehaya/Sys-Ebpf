package Sys::Ebpf::Link::Netlink::Socket;

use strict;
use warnings;
use Socket qw( SOCK_RAW );
use Errno  ();
use Exporter 'import';

use Sys::Ebpf::Link::Netlink::Constants::Netlink qw(
    NETLINK_ROUTE
    NLMSG_HDRLEN
    NLA_HDRLEN
    NLM_F_REQUEST
    NLM_F_ACK
    NETLINK_EXT_ACK
);
use Sys::Ebpf::Link::Netlink::Constants::Socket qw(
    PF_NETLINK
    AF_NETLINK
    SOL_NETLINK
);

our @EXPORT_OK = qw(
    pack_sockaddr_nl
    pack_nlattr
    pack_nlmsghdr
    pack_ifinfomsg
);

sub new {
    my ( $class, %args ) = @_;
    my $self = {};
    bless $self, $class;

    # Netlinkソケットを作成
    socket( $self->{sock}, PF_NETLINK, SOCK_RAW,
        $args{Proto} || NETLINK_ROUTE )
        or die "Failed to create Netlink socket: $!";

    # 拡張エラーメッセージを有効にする
    my $one = pack( 'i', 1 );
    setsockopt( $self->{sock}, SOL_NETLINK, NETLINK_EXT_ACK, $one )
        or warn "Failed to set NETLINK_EXT_ACK: $!";

    # ソケットをバインド
    my $sockaddr_nl = pack_sockaddr_nl($$);    # プロセスのPIDにバインド
    bind( $self->{sock}, $sockaddr_nl )
        or die "Failed to bind Netlink socket: $!";

    return $self;
}

sub send_message {
    my ( $self, $message ) = @_;

    # カーネル（pid 0）にメッセージを送信
    my $sockaddr_nl = pack_sockaddr_nl(0);
    my $bytes_sent  = send( $self->{sock}, $message, 0, $sockaddr_nl );
    unless ($bytes_sent) {
        die "Failed to send Netlink message: $!";
    }

    return $bytes_sent;
}

sub receive_message {
    my ($self) = @_;

    my $response;

    my $from = recv( $self->{sock}, $response, 8192, 0 );
    unless ( defined $from ) {
        die "Failed to receive Netlink response: $!";
    }

    return $response;
}

sub close {
    my ($self) = @_;
    close( $self->{sock} ) if $self->{sock};
}

# cf. https://github.com/torvalds/linux/blob/3efc57369a0ce8f76bf0804f7e673982384e4ac9/include/uapi/linux/netlink.h#L37
# typedef unsigned short __kernel_sa_family_t;
# struct sockaddr_nl {
# 	__kernel_sa_family_t	nl_family;	/* AF_NETLINK	*/
# 	unsigned short	nl_pad;		/* zero		*/
# 	__u32		nl_pid;		/* port ID	*/
#   __u32		nl_groups;	/* multicast groups mask */
# };
sub pack_sockaddr_nl {
    my ($pid) = @_;
    return pack( 'S x2 L L', AF_NETLINK, $pid, 0 );
}

# cf. https://github.com/torvalds/linux/blob/3efc57369a0ce8f76bf0804f7e673982384e4ac9/include/uapi/linux/netlink.h#L229
# /*
#  *  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
#  * +---------------------+- - -+- - - - - - - - - -+- - -+
#  * |        Header       | Pad |     Payload       | Pad |
#  * |   (struct nlattr)   | ing |                   | ing |
#  * +---------------------+- - -+- - - - - - - - - -+- - -+
#  *  <-------------- nlattr->nla_len -------------->
#  */
# struct nlattr {
# 	__u16           nla_len;
# 	__u16           nla_type;
# };
sub pack_nlattr {
    my ( $type, $payload ) = @_;
    my $nla_len        = NLA_HDRLEN + length($payload);    # ヘッダー＋ペイロードの長さ
    my $nla_padded_len = ( $nla_len + 3 ) & ~3;            # 4バイト境界にアライン
    my $padding        = "\0" x ( $nla_padded_len - $nla_len );    # パディング
    return
          pack( 'S S', $nla_padded_len, $type )
        . $payload
        . $padding;    # パディング後の長さでパック
}

# cf. https://github.com/torvalds/linux/blob/3efc57369a0ce8f76bf0804f7e673982384e4ac9/include/uapi/linux/netlink.h#L52
# /**
#  * struct nlmsghdr - fixed format metadata header of Netlink messages
#  * @nlmsg_len:   Length of message including header
#  * @nlmsg_type:  Message content type
#  * @nlmsg_flags: Additional flags
#  * @nlmsg_seq:   Sequence number
#  * @nlmsg_pid:   Sending process port ID
#  */
# struct nlmsghdr {
# 	__u32		nlmsg_len;
# 	__u16		nlmsg_type;
# 	__u16		nlmsg_flags;
# 	__u32		nlmsg_seq;
# 	__u32		nlmsg_pid;
# };
sub pack_nlmsghdr {
    my ( $len, $type, $flags, $seq, $pid ) = @_;
    return pack( 'L S S L L', $len, $type, $flags, $seq, $pid );
}

# cf. https://github.com/torvalds/linux/blob/3efc57369a0ce8f76bf0804f7e673982384e4ac9/include/uapi/linux/rtnetlink.h#L561
# struct ifinfomsg {
# 	unsigned char	ifi_family;
# 	unsigned char	__ifi_pad;
# 	unsigned short	ifi_type;		/* ARPHRD_* */
# 	int		ifi_index;		/* Link index	*/
# 	unsigned	ifi_flags;		/* IFF_* flags	*/
# 	unsigned	ifi_change;		/* IFF_* change mask */
# };
sub pack_ifinfomsg {
    my ( $family, $type, $index, $flags, $change ) = @_;
    return pack( 'C C S I I I', $family, 0, $type, $index, $flags, $change );
}

1;
