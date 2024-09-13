use strict;
use warnings;
use utf8;

use Test::More import => [qw( done_testing is_deeply ok plan subtest )];
use Time::HiRes qw( usleep );

use lib '../lib';
use Sys::Ebpf::Map;
use Sys::Ebpf::Constants::BpfMapType        qw(BPF_MAP_TYPE_HASH);
use Sys::Ebpf::Constants::BpfMapCreateFlags qw(BPF_F_NO_PREALLOC);
use Sys::Ebpf::Constants::BpfMapUpdateFlags qw(BPF_ANY BPF_NOEXIST BPF_EXIST);

plan skip_all => "This test must be run as root" if $> != 0;

sub create_map {
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

    my $map = Sys::Ebpf::Map->create( \%map_attr );
    usleep(10000);    # 10ms wait after creation
    return $map;
}

subtest 'test_map_creation' => sub {
    my $map = create_map();
    ok( $map->{map_fd} > 0, "Created map fd is " . $map->{map_fd} );
    ok( $map->{map_flags} == BPF_F_NO_PREALLOC, "Map flags are correct" );
    ok( $map->{key_size} == 20,                 "Key size is correct" );
    ok( $map->{value_size} == 20,               "Value size is correct" );
    $map->close();
    usleep(10000);    # 10ms wait after closure
};
subtest 'test_map_update_and_lookup' => sub {
    my $map = create_map();
    my $key = {
        uint8_id  => [ 1, 0, 2, 0 ],
        uint16_id => [ 1, 2 ],
        uint32_id => 1,
        uint64_id => 1
    };
    my $value = {
        uint8_value  => [ 1, 2, 3, 4 ],
        uint16_value => [ 1, 2 ],
        uint32_value => 1,
        uint64_value => 1
    };

    my $res = $map->update( $key, $value, BPF_ANY() );
    ok( $res == 0, "Updated map: $res" );

    my $lookup_value = $map->lookup($key);
    ok( defined $lookup_value, "Found value" );
    is_deeply( $lookup_value, $value, "Value is correct" );

    $map->close();
    usleep(10000);    # 10ms wait after closure
};
subtest 'test_map_delete' => sub {
    my $map = create_map();
    my $key = {
        uint8_id  => [ 1, 0, 2, 0 ],
        uint16_id => [ 1, 2 ],
        uint32_id => 1,
        uint64_id => 1
    };
    my $value = {
        uint8_value  => [ 1, 2, 3, 4 ],
        uint16_value => [ 1, 2 ],
        uint32_value => 1,
        uint64_value => 1
    };

    # Update the map and verify the write
    my $update_res = $map->update( $key, $value, BPF_ANY() );
    ok( $update_res == 0, "Updated map: $update_res" );

    my $verify_value = $map->lookup($key);
    ok( defined $verify_value, "Value found after update" );
    is_deeply( $verify_value, $value, "Written value is correct" );

    # Now proceed with deletion test
    my $res = $map->delete($key);
    ok( $res == 0, "Deleted map entry: $res" );

    my $lookup_value = $map->lookup($key);
    ok( !defined $lookup_value, "Value not found after deletion" );

    $map->close();
    usleep(10000);    # 10ms wait after closure
};

done_testing();
