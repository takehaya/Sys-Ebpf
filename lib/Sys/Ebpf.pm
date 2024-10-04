package Sys::Ebpf;

use strict;
use warnings;
use utf8;

our $VERSION = '0.03';

1;

__END__

=head1 NAME

ebpf - Pure-Perl interface for eBPF (extended Berkeley Packet Filter)

=head1 SYNOPSIS

  use strict;
  use warnings;
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

  my $kprobe_info = Sys::Ebpf::Link::Perf::Kprobe::attach_kprobe( $prog_fd, $kprobe_fn );

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

=head1 DESCRIPTION

The C<ebpf> module provides a Perl interface for working with eBPF (extended Berkeley Packet Filter)
on Linux systems. It allows you to load eBPF programs, create and manipulate BPF maps, and interact
with the eBPF subsystem directly from Perl.

This module includes several submodules:

=over 6

=item * C<Sys::Ebpf::Loader> - For loading eBPF programs and maps

=item * C<Sys::Ebpf::Asm> - eBPF assembly helpers

=item * C<Sys::Ebpf::Reader> - For reading ELF files

=item * C<Sys::Ebpf::Elf::Parser> - For parsing ELF files

=item * C<Sys::Ebpf::Link::Netlink> - For calling BPF-related netlink commands(e.g. XDP)

=item * C<Sys::Ebpf::Link::Perf> - For calling BPF-related perf events(e.g. kprobes)

=back

=head1 FUNCTIONS

This module primarily serves as a namespace and version container for its submodules.
Refer to the documentation of individual submodules for specific functions and usage.

=head1 SEE ALSO

=over 4

=item * L<Sys::Ebpf::loader>

=item * L<Sys::Ebpf::asm>

=item * C<Sys::Ebpf::reader> - For reading ELF files

=item * C<Sys::Ebpf::elf::parser> - For parsing ELF files

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
