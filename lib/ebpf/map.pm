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
        map_name => $args{map_name},
        map_fd => $args{map_fd},
        map_type => $args{map_type},
        key_size => $args{key_size},
        value_size => $args{value_size},
        max_entries => $args{max_entries},
        map_flags => $args{map_flags},
        key_schema => $args{key_schema},
        value_schema => $args{value_schema},
    };
    bless $self, $class;
    return $self;
}

sub create {
    my ($class, $args) = @_;

    my $defaults = {
        map_name => "",
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
        key_schema => undef,
        value_schema => undef,
    };

    my $attrs = {
        %$defaults,
        %$args,
    };

    # key_size と value_size を自動計算
    $attrs->{key_size} = _calculate_size($attrs->{key_schema}) if $attrs->{key_schema};
    $attrs->{value_size} = _calculate_size($attrs->{value_schema}) if $attrs->{value_schema};
    
    # cf. https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L1459
    my $attr = pack(
        "L L L L L L L Z16 L L L L L",
        $attrs->{map_type},
        $attrs->{key_size},
        $attrs->{value_size},
        $attrs->{max_entries},
        $attrs->{map_flags},
        $attrs->{inner_map_fd},
        $attrs->{numa_node},
        $attrs->{map_name},
        $attrs->{map_ifindex},
        $attrs->{btf_fd},
        $attrs->{btf_key_type_id},
        $attrs->{btf_value_type_id},
        $attrs->{btf_vmlinux_value_type_id}
    );

    my $map_fd = syscall(ebpf::syscall::SYS_bpf(), BPF_MAP_CREATE(), $attr, length($attr));
    if ($map_fd < 0) {
        my $errno = $!;
        die "Failed to create BPF map: $errno\n";
    }

    return $class->new(
        map_name => $attrs->{map_name},
        map_fd => $map_fd,
        map_type => $attrs->{map_type},
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

sub _calculate_size {
    my ($schema) = @_;
    my $size = 0;
    for my $field (@$schema) {
        my ($name, $type) = @$field;
        $size += _get_type_size($type);
    }
    return $size;
}

sub _serialize {
    my ($self, $data, $schema) = @_;
    my @packed;
    for my $field (@$schema) {
        my ($name, $type) = @$field;
        my $value = $data->{$name};
        push @packed, _pack_value($type, $value);
    }
    return join('', @packed);
}

sub _deserialize {
    my ($self, $packed_data, $schema) = @_;
    my $offset = 0;
    my $result = {};
    for my $field (@$schema) {
        my ($name, $type) = @$field;
        ($result->{$name}, $offset) = _unpack_value($type, $packed_data, $offset);
    }
    return $result;
}


sub _match_uint_or_uint_array {
    my ($type) = @_;
    return $type =~ /^uint(\d+)(?:\[(\d+)\])?$/ ? ($1, $2) : ();
}

sub _get_type_size {
    my ($type) = @_;

    if (my ($bit_size, $array_size) = _match_uint_or_uint_array($type)) {
        $array_size //= 1;  # default to 1
        if ($bit_size =~ /^(8|16|32|64)$/) { # fixed-size integer
            return ($bit_size / 8) * $array_size;
        }
    }elsif($type =~ /^string\((\d+)\)$/) {
        return $1;
    }

    die "Unsupported type: $type";
}

sub _pack_value {
    my ($type, $value) = @_;

    if (my ($bit_size, $array_size) = _match_uint_or_uint_array($type)) {
        $array_size //= 1; # default to 1
        my $pack_char = _get_pack_char($bit_size);
        return pack("$pack_char$array_size", @$value) if ref $value eq 'ARRAY';
        return pack($pack_char, $value);
    }

    if ($type =~ /^string\((\d+)\)$/) {
        return pack("a$1", $value);
    }

    die "Unsupported type: $type";
}

sub _get_pack_char {
    my ($bit_size) = @_;
    return 'C' if $bit_size == 8;
    return 'S' if $bit_size == 16;
    return 'L' if $bit_size == 32;
    return 'Q' if $bit_size == 64;
    die "Unsupported bit size: $bit_size";
}

sub _unpack_value {
    my ($type, $data, $offset) = @_;

    if (my ($bit_size, $array_size) = _match_uint_or_uint_array($type)) {
        $array_size //= 1;
        my $pack_char = _get_pack_char($bit_size);
        return unpack_at("$pack_char$array_size", $data, $offset, ($bit_size / 8) * $array_size);
    }

    if ($type =~ /^string\((\d+)\)$/) {
        my $len = $1;
        return unpack_at("A$len", $data, $offset, $len);
    }

    die "Unsupported type: $type";
}

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
