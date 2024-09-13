[![Actions Status](https://github.com/takehaya/perl-ebpf/actions/workflows/test.yml/badge.svg)](https://github.com/takehaya/perl-ebpf/actions)
# NAME

ebpf - Pure-Perl interface for eBPF (extended Berkeley Packet Filter)

# SYNOPSIS

    use Sys::Ebpf::;

    # Create a new eBPF loader
    my $loader = Sys::Ebpf::loader->new();

    # Load a BPF map
    my $map_fd = $loader->load_bpf_map({
        map_type => Sys::Ebpf::Constants::bpf_map_type::BPF_MAP_TYPE_ARRAY,
        key_size => 4,
        value_size => 8,
        max_entries => 1,
        map_flags => 0,
        map_name => "my_map"
    });

    # Pin the map to a file
    $loader->pin_bpf_map($map_fd, "/sys/fs/bpf/my_map");

    # TBA...

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
