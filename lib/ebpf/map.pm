package ebpf::map;

use strict;
use warnings;
our $VERSION = $ebpf::VERSION;

use ebpf::constants::bpf_cmd qw(
    BPF_MAP_CREATE 
    BPF_MAP_LOOKUP_ELEM 
    BPF_MAP_UPDATE_ELEM
    BPF_MAP_DELETE_ELEM
    BPF_MAP_GET_NEXT_KEY 
    BPF_OBJ_PIN
);
use ebpf::constants::bpf_map_type qw(:all);
use ebpf::constants::bpf_map_update_flags qw(:all);
use ebpf::constants::bpf_map_create_flags qw(:all);
use ebpf::syscall;

sub new {
    my ($class, %args) = @_;
    my $self = {
        name => $args{name},
        fd => $args{fd},
        type => $args{type},
        key_size => $args{key_size},
        value_size => $args{value_size},
        max_entries => $args{max_entries},
        map_flags => $args{map_flags} || 0,
    };
    bless $self, $class;
    return $self;
}

sub create {
    my ($class, $args) = @_;

    my $defaults = {
        name => "",
        map_type => BPF_MAP_TYPE_UNSPEC(),
        key_size => 0,
        value_size => 0,
        max_entries => 0,
        map_flags => 0,
        inner_map_fd => -1,
        numa_node => 0,
        map_ifindex => 0,
        btf_fd => 0,
        btf_key_type_id => 0,
        btf_value_type_id => 0,
        btf_vmlinux_value_type_id => 0,
    };

    my $attrs = {
        %$defaults,
        %$args,
    };

    my $attr = pack(
        "L L L L L L L Z16 L L L L L",
        $attrs->{map_type},
        $attrs->{key_size},
        $attrs->{value_size},
        $attrs->{max_entries},
        $attrs->{map_flags},
        $attrs->{inner_map_fd},
        $attrs->{numa_node},
        $attrs->{name},
        $attrs->{map_ifindex},
        $attrs->{btf_fd},
        $attrs->{btf_key_type_id},
        $attrs->{btf_value_type_id},
        $attrs->{btf_vmlinux_value_type_id}
    );

    my $map_fd = syscall(ebpf::syscall::SYS_bpf(), BPF_MAP_CREATE(), $attr, length($attr));
    die "Failed to create BPF map: $!" if $map_fd < 0;

    return $class->new(
        name => $attrs->{name},
        fd => $map_fd,
        type => $attrs->{type},
        key_size => $attrs->{key_size},
        value_size => $attrs->{value_size},
        max_entries => $attrs->{max_entries},
        map_flags => $attrs->{map_flags},
    );
}

sub lookup {
    my ($self, $key, $flags) = @_;
    $flags //= 0;
    my $value = "\0" x $self->{value_size};
    my $attr = pack("QQQQ", unpack("Q", pack("P", $key)), unpack("Q", pack("P", $value)), $flags, 0);
    my $res = syscall(ebpf::syscall::SYS_bpf(), BPF_MAP_LOOKUP_ELEM(), $attr, length($attr));
    return $res == 0 ? $value : undef;
}

sub update {
    my ($self, $key, $value, $flags) = @_;
    $flags //= BPF_ANY();
    my $attr = pack("QQQQ", unpack("Q", pack("P", $key)), unpack("Q", pack("P", $value)), $flags, 0);
    my $res = syscall(ebpf::syscall::SYS_bpf(), BPF_MAP_UPDATE_ELEM(), $attr, length($attr));
    return $res == 0;
}

sub delete {
    my ($self, $key) = @_;
    my $attr = pack("QQQ", unpack("Q", pack("P", $key)), 0, 0);
    my $res = syscall(ebpf::syscall::SYS_bpf(), BPF_MAP_DELETE_ELEM(), $attr, length($attr));
    return $res == 0;
}

sub get_next_key {
    my ($self, $key) = @_;
    my $next_key = "\0" x $self->{key_size};
    my $attr = pack("QQQ", unpack("Q", pack("P", $key)), unpack("Q", pack("P", $next_key)), 0);
    my $res = syscall(ebpf::syscall::SYS_bpf(), BPF_MAP_GET_NEXT_KEY(), $attr, length($attr));
    return $res == 0 ? $next_key : undef;
}

sub get_fd { $_[0]->{fd} }
sub get_name { $_[0]->{name} }
sub get_type { $_[0]->{type} }
sub get_key_size { $_[0]->{key_size} }
sub get_value_size { $_[0]->{value_size} }
sub get_max_entries { $_[0]->{max_entries} }
sub get_map_flags { $_[0]->{map_flags} }

# TODO: enable file_flags
sub pin_bpf_map {
    my ($map_fd, $pin_path) = @_;

    my $path_buf = pack("Z*", $pin_path);
    my $attr = pack("Q L L",
        unpack("Q", pack("P", $path_buf)),
        $map_fd,
        0                                   # file_flags
    );

    my $res = syscall(ebpf::syscall::SYS_bpf(), BPF_OBJ_PIN, $attr, length($attr));

    if ($res < 0) {
        my $errno = $!;
        die "Failed to pin BPF map: $errno\n";
    }

    return $res;
}

# BPF_OBJ_PIN のunpinの実装
# return:
#   0: success
#   -1: failed
sub unpin_bpf_map {
    my ($pin_path) = @_;

    if (unlink($pin_path)) {
        return 0;
    }
    return -1;
}

1;
