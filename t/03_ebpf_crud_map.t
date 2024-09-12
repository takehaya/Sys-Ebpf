use strict;
use warnings;
use utf8;

use Test::More import => [qw( done_testing is_deeply ok plan )];
use Data::Dumper ();

# Load the module you're testing
use lib '../lib';
use sys::ebpf::asm;
use sys::ebpf::map;

use sys::ebpf::constants::bpf_map_type         qw( BPF_MAP_TYPE_HASH );
use sys::ebpf::constants::bpf_map_create_flags qw(BPF_F_NO_PREALLOC);
use sys::ebpf::constants::bpf_prog_type        ();
use sys::ebpf::constants::bpf_map_update_flags
    qw(BPF_ANY BPF_NOEXIST BPF_EXIST);

plan skip_all => "This test must be run as root" if $> != 0;

my $map_instance;

sub setup {
    my %map_attr = (
        map_name    => "ebpf_crud_map",
        map_type    => BPF_MAP_TYPE_HASH,
        max_entries => 1,
        key_schema  => [
            [ 'uint8_id',  'uint8[4]' ],
            [ 'uint16_id', 'uint16[2]' ],
            [ 'uint32_id', 'uint32' ],
            [ 'uint64_id', 'uint64' ],
        ],
        value_schema => [
            [ 'uint8_value',  'uint8[4]' ],
            [ 'uint16_value', 'uint16[2]' ],
            [ 'uint32_value', 'uint32' ],
            [ 'uint64_value', 'uint64' ],
        ],
        map_flags => BPF_F_NO_PREALLOC,
    );

    $map_instance = sys::ebpf::map->create( \%map_attr );
}

sub teardown {
    if ($map_instance) {
        $map_instance->close();
        undef $map_instance;

        # sleep 1;
    }
}

sub run_test {
    setup();

    # テストコード
    my $map_fd = $map_instance->{map_fd};
    ok( $map_fd > 0, "Created map fd is $map_fd" );
    ok( $map_instance->{map_flags} == BPF_F_NO_PREALLOC,
        "Map flags are correct",
    );
    ok( $map_instance->{key_size} == 20,   "Key size is correct" );
    ok( $map_instance->{value_size} == 20, "Value size is correct" );

    my $origin_key = {
        uint8_id  => 1,
        uint16_id => [ 1, 2 ],
        uint32_id => 1,
        uint64_id => 1
    };
    my $origin_value = {
        uint8_value  => [ 1, 2, 3, 4 ],
        uint16_value => [ 1, 2 ],
        uint32_value => 1,
        uint64_value => 1
    };
    my $res = $map_instance->update( $origin_key, $origin_value, BPF_ANY() );

    ok( $res >= 0, "Updated map: $res" );

    my $value = $map_instance->lookup($origin_key);
    ok( defined $value, "Found value" );
    is_deeply( $value, $origin_value, "Value is correct" );

    $res = $map_instance->delete($origin_key);
    ok( $res == 0, "Deleted map: $res" );

    $value = $map_instance->lookup($origin_key);
    ok( !defined $value, "Value not found after deletion" );

    teardown();
}

run_test();

END {
    teardown();
}
done_testing();
