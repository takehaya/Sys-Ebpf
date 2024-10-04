[![Actions Status](https://github.com/takehaya/perl-ebpf/actions/workflows/test.yml/badge.svg)](https://github.com/takehaya/perl-ebpf/actions)
# NAME

ebpf - Pure-Perl interface for eBPF (extended Berkeley Packet Filter)

# SYNOPSIS

    use utf8;
    use Sys::Ebpf::Loader;
    use Sys::Ebpf::Link::Perf::Kprobe;

    my $file   = "kprobe.o";
    my $loader = Sys::Ebpf::Loader->new($file);
    my $data   = $loader->load_elf();

    my $kprobe_fn = "kprobe/sys_execve";

    my ( $map_data, $prog_fd ) = $loader->load_bpf($kprobe_fn);
    my $map_kprobe_map = $map_data->{kprobe_map};
    $map_kprobe_map->{key_schema}   = [ [ 'kprobe_map_key',   'uint32' ], ];
    $map_kprobe_map->{value_schema} = [ [ 'kprobe_map_value', 'uint64' ], ];

    # Pin the map to a file
    $loader->pin_bpf_map($map_fd, "/sys/fs/bpf/my_map");

    # attach kprobe
    my $kprobe_info = Sys::Ebpf::Link::Perf::Kprobe::attach_kprobe( $prog_fd, $kprobe_fn );

    # show map code from kprobe
    while (1) {
        my $key   = { kprobe_map_key => 0 };
        my $value = $map_kprobe_map->lookup($key);
        if ( defined $value ) {
            print Dumper($value);
            printf "%s called %d times\n", $kprobe_fn, $value->{kprobe_map_value};
        }
        else {
            warn "Failed to read map value\n";
        }
        sleep(1);
    }

# DESCRIPTION

The `ebpf` module provides a Perl interface for working with eBPF (extended Berkeley Packet Filter)
on Linux systems. It allows you to load eBPF programs, create and manipulate BPF maps, and interact
with the eBPF subsystem directly from Perl.

This module includes several submodules:

- `Sys::Ebpf::loader` - For loading eBPF programs and maps
- `Sys::Ebpf::asm` - eBPF assembly helpers
- `Sys::Ebpf::reader` - For reading ELF files
- `Sys::Ebpf::elf::parser` - For parsing ELF files

# FUNCTIONS

This module primarily serves as a namespace and version container for its submodules.
Refer to the documentation of individual submodules for specific functions and usage.

# SEE ALSO

- [Sys::Ebpf::loader](https://metacpan.org/pod/Sys%3A%3AEbpf%3A%3Aloader)
- [Sys::Ebpf::asm](https://metacpan.org/pod/Sys%3A%3AEbpf%3A%3Aasm)
- `Sys::Ebpf::reader` - For reading ELF files
- `Sys::Ebpf::elf::parser` - For parsing ELF files

# AUTHOR

TAKERU HAYASAKA <hayatake396@gmail.com>

# LICENSE AND COPYRIGHT

Copyright (C) 2024 TAKERU HAYASAKA

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See [http://dev.perl.org/licenses/](http://dev.perl.org/licenses/) for more information.
