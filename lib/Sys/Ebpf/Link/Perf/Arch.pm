package Sys::Ebpf::Link::Perf::Arch;

use strict;
use warnings;
use utf8;

use Config qw( %Config );

sub platform_prefix {
    my $arch = $Config{archname};
    if ( $arch =~ /^i[3456]86/ ) {
        return "__ia32_";
    }
    elsif ( $arch =~ /^x86_64/ ) {
        return "__x64_";
    }
    elsif ( $arch =~ /^arm/ ) {
        return "__arm_";
    }
    elsif ( $arch =~ /^aarch64/ ) {
        return "__arm64_";
    }
    elsif ( $arch =~ /^mips/ ) {
        return "__mips_";
    }
    elsif ( $arch =~ /^s390/ ) {
        return "__s390_";
    }
    elsif ( $arch =~ /^powerpc/ ) {
        return $arch =~ /64/ ? "__powerpc64_" : "__powerpc_";
    }
    elsif ( $arch =~ /^riscv/ ) {
        return "__riscv_";
    }
    else {
        return "";
    }
}

1;
