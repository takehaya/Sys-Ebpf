use strict;
use warnings;
use utf8;

use Test::More import => [qw( done_testing is is_deeply subtest )];
use Data::Dumper ();

use lib '../lib';
use ebpf::map;

my $map = ebpf::map->new(
    key_schema => [
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
);

subtest '_match_uint_or_uint_array tests' => sub {
    my @test_cases = (
        { type => 'uint8',     bitsize => 8,  array_size => undef },
        { type => 'uint16',    bitsize => 16, array_size => undef },
        { type => 'uint32',    bitsize => 32, array_size => undef },
        { type => 'uint64',    bitsize => 64, array_size => undef },
        { type => 'uint8[1]',  bitsize => 8,  array_size => 1 },
        { type => 'uint16[1]', bitsize => 16, array_size => 1 },
        { type => 'uint32[1]', bitsize => 32, array_size => 1 },
        { type => 'uint64[1]', bitsize => 64, array_size => 1 },
        { type => 'uint8[4]',  bitsize => 8,  array_size => 4 },
        { type => 'uint16[4]', bitsize => 16, array_size => 4 },
        { type => 'uint32[4]', bitsize => 32, array_size => 4 },
        { type => 'uint64[4]', bitsize => 64, array_size => 4 },
    );

    for my $case (@test_cases) {
        my ( $bit_size, $array_size )
            = ebpf::map::_match_uint_or_uint_array( $case->{type} );
        is( $bit_size, $case->{bitsize},
            "Correct bit size for $case->{type}" );
        is( $array_size, $case->{array_size},
            "Correct array size for $case->{type}" );
    }
};

subtest '_pack_value and _unpack_value tests' => sub {
    my @test_cases = (
        {   type     => 'uint8[4]',
            value    => [ 1, 2, 3, 4 ],
            expected => pack( 'C4', 1, 2, 3, 4 )
        },
        {   type     => 'uint16[2]',
            value    => [ 256, 512 ],
            expected => pack( 'S2', 256, 512 )
        },
        { type => 'uint32', value => 12345, expected => pack( 'L', 12345 ) },
        {   type     => 'uint64',
            value    => 1234567890,
            expected => pack( 'Q', 1234567890 )
        },
    );

    for my $case (@test_cases) {
        my $packed = ebpf::map::_pack_value( $case->{type}, $case->{value} );
        is( $packed, $case->{expected}, "Correctly packed $case->{type}" );

        my ( $unpacked, $offset )
            = ebpf::map::_unpack_value( $case->{type}, $packed, 0 );
        is_deeply( $unpacked, $case->{value},
            "Correctly unpacked $case->{type}" );
    }
};

subtest '_serialize and _deserialize tests' => sub {
    my $test_data = {
        uint8_id  => [ 1,   2, 3, 4 ],
        uint16_id => [ 256, 512 ],
        uint32_id => 12345,
        uint64_id => 1234567890,
    };

    my $serialized = $map->_serialize( $test_data, $map->{key_schema} );
    is( length($serialized), 20, "Serialized key has correct length" );

    my $deserialized = $map->_deserialize( $serialized, $map->{key_schema} );
    is_deeply( $deserialized, $test_data,
        "Deserialized data matches original" );
};

done_testing();
