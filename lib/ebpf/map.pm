package ebpf::map;

use strict;
use warnings;
use POSIX;
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

sub close {
    my ($self) = @_;
    if (defined $self->{map_fd} && $self->{map_fd} > 0) {
        my $res = POSIX::close($self->{map_fd});
        if ($res == -1) {
            warn "Failed to close BPF map (fd: $self->{map_fd}): $!\n";
            return 0;
        }
        $self->{map_fd} = undef;
        return 1;
    }
    return 1;
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
        key_schema => $attrs->{key_schema},
        value_schema => $attrs->{value_schema},
    );
}

# cf. https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L1501
sub syscall_bpf_map_elem {
    my ($cmd, $map_fd, $key, $value, $flags) = @_;

    my $attr = pack("L L Q Q Q",
        $map_fd,                        # union bpf_attr::map_fd(32bit)
        0,                              # padding (32bit)
        unpack("Q", pack("P", $key)),   # union bpf_attr::key(64bit)
        defined($value) ? unpack("Q", pack("P", $value)) : 0, # union bpf_attr::value(64bit), 0 if undef, delete operation case
        $flags,                         # union bpf_attr::flags(64bit)
    );
    my $result = syscall(ebpf::syscall::SYS_bpf(), $cmd, $attr, length($attr));
    return $result;
}


sub raw_lookup {
    my ($self, $key, $flags) = @_;
    $flags //= 0;
    my $value = "\0" x $self->{value_size};
    my $res = syscall_bpf_map_elem(BPF_MAP_LOOKUP_ELEM(), $self->{map_fd}, $key, $value, $flags);
    if ($res < 0) {
        my $errno = $!;
        warn "syscall_bpf_map_elem failed with errno $errno: $!";
    }

    return $res == 0 ? $value : undef;
}

sub raw_update {
    my ($self, $key, $value, $flags) = @_;
    $flags //= BPF_ANY();
    my $res = syscall_bpf_map_elem(BPF_MAP_UPDATE_ELEM(), $self->{map_fd}, $key, $value, $flags);
    if ($res < 0) {
        my $errno = $!;
        warn "Failed to update BPF map: $errno\n";
    }
    return $res;
}

sub raw_delete {
    my ($self, $key, $flags) = @_;
    $flags //= BPF_ANY();
    my $res = syscall_bpf_map_elem(BPF_MAP_DELETE_ELEM(), $self->{map_fd}, $key, undef, $flags);
    if ($res < 0) {
        my $errno = $!;
        warn "Failed to delete BPF map entry with key ", unpack("H*", $key), ": $errno ($!)\n";
    }
    return $res;
}

sub raw_get_next_key {
    my ($self, $key) = @_;
    my $next_key = "\0" x $self->{key_size};
    my $res = syscall_bpf_map_elem(BPF_MAP_GET_NEXT_KEY(), $self->{map_fd}, $key, $next_key, 0);
    return $res == 0 ? $next_key : undef;
}

sub update {
    my ($self, $key, $value, $flags) = @_;
    $flags //= BPF_ANY();

    # Serialize key and value
    if (!defined $self->{key_schema} || !defined $self->{value_schema}) {
        die "Key and value schema must be defined to use update method\n";
    }
    my $packed_key = $self->_serialize($key, $self->{key_schema});
    my $packed_value = $self->_serialize($value, $self->{value_schema});

    return $self->raw_update($packed_key, $packed_value, $flags);
}

sub lookup {
    my ($self, $key) = @_;
    if (!defined $self->{key_schema} || !defined $self->{value_schema}) {
        die "Key and value schema must be defined to use update method\n";
    }
    my $packed_key = $self->_serialize($key, $self->{key_schema});
    my $packed_value = $self->raw_lookup($packed_key);
    if (!defined $packed_value) {
        return undef;
    }
    if ($self->{value_schema}) {
        return $self->_deserialize($packed_value, $self->{value_schema});
    }
    return $packed_value;
}

sub delete {
    my ($self, $key, $flags) = @_;
    $flags //= BPF_ANY();
    if (!defined $self->{key_schema} || !defined $self->{value_schema}) {
        die "Key and value schema must be defined to use update method\n";
    }
    my $packed_key = $self->_serialize($key, $self->{key_schema});
    return $self->raw_delete($packed_key, $flags);
}

sub get_next_key {
    my ($self, $key) = @_;
    my $packed_key = defined $key ? $self->_serialize($key, $self->{key_schema}) : undef;
    my $next_packed_key = $self->raw_get_next_key($packed_key);
    return undef unless defined $next_packed_key;
    return $self->_deserialize($next_packed_key, $self->{key_schema});
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
        my $packed_value = _pack_value($type, $value);
        push @packed, $packed_value;
    }
    return join('', @packed);
}

sub _deserialize {
    my ($self, $packed_data, $schema) = @_;
    my $offset = 0;
    my $result = {};
    for my $field (@$schema) {
        my ($name, $type) = @$field;
        my ($value, $new_offset) = _unpack_value($type, $packed_data, $offset);
        $result->{$name} = $value;
        $offset = $new_offset;
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
        my $byte_size = ($bit_size / 8) * $array_size;
        my @values = unpack("$pack_char$array_size", substr($data, $offset, $byte_size));

        # If array_size > 1, return array reference
        if ($array_size > 1) {
            return (\@values, $offset + $byte_size);
        }

        # Otherwise, return the single value
        return ($values[0], $offset + $byte_size);
    }

    die "Unsupported type: $type";
}
sub unpack_at {
    my ($template, $data, $offset, $length) = @_;
    my $extracted = substr($data, $offset, $length);
    my @unpacked = unpack($template, $extracted);

    #リストコンテキストで呼び出された場合（@unpacked の全要素が必要な場合）、全ての解凍された値を返します
    # スカラーコンテキストで呼び出された場合（単一の値のみが必要な場合）、最初の解凍された値のみを返します
    return (wantarray ? @unpacked : $unpacked[0], $offset + $length);
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
