package Sys::Ebpf::Link::Perf::Kprobe;

use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';

use Sys::Ebpf::Link::Perf::Arch qw( platform_prefix );
use Sys::Ebpf::Syscall;
use Sys::Ebpf::Link::Perf::Constants::PerfEventIoctl qw(
    PERF_EVENT_IOC_ENABLE
    PERF_EVENT_IOC_DISABLE
    PERF_EVENT_IOC_SET_BPF
);

use Sys::Ebpf::Link::Perf::Constants::PerfEvent qw(
    PERF_TYPE_TRACEPOINT
    PERF_SAMPLE_RAW
    PERF_FLAG_FD_CLOEXEC
);

sub attach_kprobe {
    my ( $prog_fd, $kprobe_fn ) = @_;

    # Extract kprobe function name
    my $func_name;
    if ( $kprobe_fn =~ m{^kprobe/(.+)$} ) {
        $func_name = $1;
    }
    else {
        die "Invalid kprobe function name: $kprobe_fn";
    }

    my $prefix = Sys::Ebpf::Link::Perf::Arch::platform_prefix();
    $func_name = $prefix . $func_name unless $func_name =~ /^$prefix/;

    # Generate a unique event name
    my $current_pid = $$;
    my $event_name  = "p_${func_name}_${current_pid}";

    # Dynamically obtain the path to the kprobe_events file
    my $kprobe_events;
    if ( -e '/sys/kernel/debug/tracing/kprobe_events' ) {
        $kprobe_events = '/sys/kernel/debug/tracing/kprobe_events';
    }
    elsif ( -e '/sys/kernel/tracing/kprobe_events' ) {
        $kprobe_events = '/sys/kernel/tracing/kprobe_events';
    }
    else {
        die "kprobe_events file not found";
    }

    # Create kprobe event
    open my $kprobe_fh, '>>', $kprobe_events
        or die "Cannot open kprobe_events: $!";
    $kprobe_fh->autoflush(1);
    print $kprobe_fh "p:$event_name $func_name\n"
        or die "Failed to write to kprobe_events: $!";
    close $kprobe_fh or warn "Failed to close kprobe_events: $!";

    # Obtain event ID
    my $id_file = $kprobe_events;
    $id_file =~ s/kprobe_events/events\/kprobes\/$event_name\/id/;
    unless ( -e $id_file ) {
        die "Event ID file does not exist. Failed to create kprobe event.";
    }
    open my $id_fh, '<', $id_file or die "Cannot open event ID file: $!";
    my $id = <$id_fh>;
    chomp $id;
    close $id_fh;

    my $pack_str = "L" .    # type, __u32
        "L" .               # size, __u32
        "Q" .               # config, __u64
        "Q" .               # sample_period, __u64
        "Q" .               # sample_type, __u64
        "Q" .               # read_format, __u64
        "Q" .               # Bit field (disabled, inherit, etc.), __u64
        "L" .               # wakeup_events, __u32
        "L" .               # bp_type, __u32
        "Q" .    # config1 (bp_addr / kprobe_func / uprobe_path), __u64
        "Q" .    # config2 (bp_len / kprobe_addr / probe_offset), __u64
        "Q" .    # branch_sample_type, __u64
        "Q" .    # sample_regs_user, __u64
        "L" .    # sample_stack_user, __u32
        "L" .    # clockid, __s32
        "Q" .    # sample_regs_intr, __u64
        "L" .    # aux_watermark, __u32
        "S" .    # sample_max_stack, __u16
        "S" .    # __reserved_2, __u16
        "L" .    # aux_sample_size, __u32
        "L" .    # __reserved_3, __u32
        "Q" .    # sig_data, __u64
        "Q";     # config3, __u64
    my $attr_size = 0;
    $attr_size += { C => 1, S => 2, L => 4, Q => 8 }->{$_}
        for split //, $pack_str;
    my $attr = pack(
        $pack_str,
        PERF_TYPE_TRACEPOINT,    # type, __u32
        $attr_size,              # size (total size of the structure), __u32
        $id,                     # config (kprobe_id), __u64
        1,                       # sample_period, __u64
        PERF_SAMPLE_RAW,         # sample_type, __u64
        0,                       # read_format, __u64
        0,                       # Bit field (disabled, inherit, etc.), __u64
        1,                       # wakeup_events, __u32
        0,                       # bp_type, __u32
        0,    # config1 (bp_addr / kprobe_func / uprobe_path), __u64
        0,    # config2 (bp_len / kprobe_addr / probe_offset), __u64
        0,    # branch_sample_type, __u64
        0,    # sample_regs_user, __u64
        0,    # sample_stack_user, __u32
        0,    # clockid, __s32
        0,    # sample_regs_intr, __u64
        0,    # aux_watermark, __u32
        0,    # sample_max_stack, __u16
        0,    # __reserved_2, __u16
        0,    # aux_sample_size, __u32
        0,    # __reserved_3, __u32
        0,    # sig_data, __u64
        0,    # config3, __u64
    );

    # Call perf_event_open system call
    my $target_pid = -1;                     # Monitor all processes
    my $cpu        = 0;                      # Monitor on all CPUs
    my $group_fd   = -1;
    my $flags      = PERF_FLAG_FD_CLOEXEC;

    my $perf_fd = syscall( Sys::Ebpf::Syscall::SYS_perf_event_open(),
        $attr, $target_pid, $cpu, $group_fd, $flags );
    if ( $perf_fd < 0 ) {
        my $errno     = $! + 0;
        my $error_msg = $!;
        die sprintf( "Failed to open perf event: %s (errno: %d)\n",
            $error_msg, $errno );
    }

    # Attach BPF program to perf event
    $! = 0;    # reset errno
    my $res = syscall(
        Sys::Ebpf::Syscall::SYS_ioctl(), $perf_fd,
        PERF_EVENT_IOC_SET_BPF,          $prog_fd
    );
    my $errno = $! + 0;
    if ( !defined $res || $res < 0 ) {
        my $error_msg = $!;
        die sprintf( "Failed to attach BPF program: %s (errno: %d)\n",
            $error_msg, $errno );
    }

    # Enable perf event
    $!   = 0;                                          # reset errno
    $res = syscall( Sys::Ebpf::Syscall::SYS_ioctl(),
        $perf_fd, PERF_EVENT_IOC_ENABLE, 0 );
    $errno = $! + 0;
    if ( !defined $res || $res < 0 ) {
        my $error_msg = $!;
        die sprintf( "Failed to enable perf event: %s (errno: %d)\n",
            $error_msg, $errno );
    }

    # Return information necessary for detachment
    return {
        perf_fd       => $perf_fd,
        event_name    => $event_name,
        kprobe_fn     => $kprobe_fn,
        kprobe_events => $kprobe_events,
    };
}

sub detach_kprobe {
    my ($kprobe_info) = @_;

    my $perf_fd       = $kprobe_info->{perf_fd};
    my $event_name    = $kprobe_info->{event_name};
    my $kprobe_events = $kprobe_info->{kprobe_events};

    # Disable perf event
    my $res = syscall( Sys::Ebpf::Syscall::SYS_ioctl(),
        $perf_fd, PERF_EVENT_IOC_DISABLE(), 0 );
    if ( $res != 0 ) {
        warn "Failed to disable perf event: $!";
    }

    # Close the file descriptor of the perf event
    close($perf_fd);

    # Remove kprobe event
    open my $fh, '>>', $kprobe_events or warn "Cannot open kprobe_events: $!";
    $fh->autoflush(1);
    print $fh "-:$event_name\n"
        or warn "Failed to write to kprobe_events: $!";
    close $fh or warn "Failed to close kprobe_events: $!";
}
1;
