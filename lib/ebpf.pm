package ebpf;

use strict;
use warnings;

our $VERSION = '0.01';

1;

__END__

=head1 NAME

ebpf - Pure-Perl interface for eBPF (extended Berkeley Packet Filter)

=head1 SYNOPSIS

  use ebpf;

  # Create a new eBPF loader
  my $loader = ebpf::loader->new();

  # Load a BPF map
  my $map_fd = $loader->load_bpf_map({
      map_type => ebpf::constants::bpf_map_type::BPF_MAP_TYPE_ARRAY,
      key_size => 4,
      value_size => 8,
      max_entries => 1,
      map_flags => 0,
      map_name => "my_map"
  });

  # Pin the map to a file
  $loader->pin_bpf_map($map_fd, "/sys/fs/bpf/my_map");

  # TBA...

=head1 DESCRIPTION

The C<ebpf> module provides a Perl interface for working with eBPF (extended Berkeley Packet Filter)
on Linux systems. It allows you to load eBPF programs, create and manipulate BPF maps, and interact
with the eBPF subsystem directly from Perl.

This module includes several submodules:

=over 6

=item * C<ebpf::loader> - For loading eBPF programs and maps

=item * C<ebpf::asm> - eBPF assembly helpers

=item * C<ebpf::reader> - For reading ELF files

=item * C<ebpf::elf::parser> - For parsing ELF files

=back

=head1 FUNCTIONS

This module primarily serves as a namespace and version container for its submodules.
Refer to the documentation of individual submodules for specific functions and usage.

=head1 SEE ALSO

=over 4

=item * L<ebpf::loader>

=item * L<ebpf::asm>

=item * C<ebpf::reader> - For reading ELF files

=item * C<ebpf::elf::parser> - For parsing ELF files

=back

=head1 AUTHOR

TAKERU HAYASAKA E<lt>hayatake396@gmail.comE<gt>

=head1 LICENSE AND COPYRIGHT

Copyright (C) 2024 TAKERU HAYASAKA

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See L<http://dev.perl.org/licenses/> for more information.

=cut