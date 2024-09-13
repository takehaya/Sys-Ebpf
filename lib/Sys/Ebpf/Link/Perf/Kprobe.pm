package Sys::Ebpf::Link::Perf::Kprobe;

use strict;
use warnings;
use utf8;

use POSIX                       qw( close fcntl open sprintf );
use Fcntl                       qw( F_GETFL );
use IO::Handle                  qw( print );
use Sys::Ebpf::Link::Perf::Arch qw( platform_prefix );
use open ':std', ':encoding(UTF-8)';

use constant {
    PERF_EVENT_IOC_ENABLE  => 0x2400,
    PERF_EVENT_IOC_DISABLE => 0x2401,
    PERF_EVENT_IOC_SET_BPF => 0x40042408,
    PERF_TYPE_TRACEPOINT   => 2,
    PERF_SAMPLE_RAW        => 1 << 10,
    PERF_FLAG_FD_CLOEXEC   => 0x00000008,
    SYS_perf_event_open    => 298,    # x86_64 システムの場合。他のアーキテクチャでは異なる可能性があります。
    SYS_ioctl              => 16,
};

sub attach_kprobe {
    my ( $prog_fd, $kprobe_fn ) = @_;

    # kprobe 関数名の抽出
    my $func_name;
    if ( $kprobe_fn =~ m{^kprobe/(.+)$} ) {
        $func_name = $1;
    }
    else {
        die "無効な kprobe 関数名です: $kprobe_fn";
    }

    my $prefix = Sys::Ebpf::Link::Perf::Arch::platform_prefix();
    $func_name = $prefix . $func_name unless $func_name =~ /^$prefix/;

    # ユニークなイベント名を生成
    my $current_pid = $$;
    my $event_name  = "p_${func_name}_${current_pid}";

    # kprobe_events ファイルのパスを動的に取得
    my $kprobe_events;
    if ( -e '/sys/kernel/debug/tracing/kprobe_events' ) {
        $kprobe_events = '/sys/kernel/debug/tracing/kprobe_events';
    }
    elsif ( -e '/sys/kernel/tracing/kprobe_events' ) {
        $kprobe_events = '/sys/kernel/tracing/kprobe_events';
    }
    else {
        die "kprobe_events ファイルが見つかりません";
    }

    print "kprobe_events: $kprobe_events\n";
    print "p:$event_name $func_name\n";

    # kprobe イベントの作成
    open my $fh, '>>', $kprobe_events or die "kprobe_events を開けません: $!";
    $fh->autoflush(1);
    print $fh "p:$event_name $func_name\n"
        or die "kprobe_events への書き込みに失敗しました: $!";
    close $fh or warn "kprobe_events のクローズに失敗しました: $!";

    # イベント ID の取得
    my $id_file = $kprobe_events;
    $id_file =~ s/kprobe_events/events\/kprobes\/$event_name\/id/;
    unless ( -e $id_file ) {
        die "イベント ID ファイルが存在しません。kprobe イベントの作成に失敗した可能性があります。";
    }
    open my $id_fh, '<', $id_file or die "イベント ID ファイルを開けません: $!";
    my $id = <$id_fh>;
    chomp $id;
    close $id_fh;

    my $pack_str = "L" . # type, __u32
        "L" .            #size, __u32
        "Q" .            #config, __u64
        "Q" .            #sample_period, __u64
        "Q" .            #sample_type, __u64
        "Q" .            #read_format, __u64
        "Q" .            #ビットフィールド (disabled, inherit, etc.), __u64
        "L" .            #wakeup_events, __u32
        "L" .            #bp_type, __u32
        "Q" .            #config1 (bp_addr / kprobe_func / uprobe_path), __u64
        "Q" .            #config2 (bp_len / kprobe_addr / probe_offset), __u64
        "Q" .            #branch_sample_type, __u64
        "Q" .            #sample_regs_user, __u64
        "L" .            #sample_stack_user, __u32
        "L" .            #clockid, __s32
        "Q" .            #sample_regs_intr, __u64
        "L" .            #aux_watermark. __u32
        "S" .            #sample_max_stack, __u16
        "S" .            #__reserved_2, __u16
        "L" .            #aux_sample_size, __u32
        "L" .            #__reserved_3, __u32
        "Q" .            #sig_data, __u64
        "Q";             #config3, __u64
    my $attr_size = 0;
    $attr_size += { C => 1, S => 2, L => 4, Q => 8 }->{$_}
        for split //, $pack_str;
    print "attr_size: $attr_size\n";
    my $attr = pack(
        $pack_str,
        PERF_TYPE_TRACEPOINT,    # type, __u32
        $attr_size,              # size (構造体全体のサイズ), __u32
        $id,                     # config (kprobe_id), __u64
        1,                       # sample_period, __u64
        PERF_SAMPLE_RAW,         # sample_type, __u64
        0,                       # read_format, __u64
        0,                       # ビットフィールド (disabled, inherit, etc.), __u64
        1,                       # wakeup_events, __u32
        0,                       # bp_type, __u32
        0,    # config1 (bp_addr / kprobe_func / uprobe_path), __u64
        0,    # config2 (bp_len / kprobe_addr / probe_offset), __u64
        0,    # branch_sample_type, __u64
        0,    # sample_regs_user, __u64
        0,    # sample_stack_user, __u32
        0,    # clockid, __s32
        0,    # sample_regs_intr, __u64
        0,    # aux_watermark. __u32
        0,    # sample_max_stack, __u16
        0,    # __reserved_2, __u16
        0,    # aux_sample_size, __u32
        0,    # __reserved_3, __u32
        0,    # sig_data, __u64
        0,    # config3, __u64
    );

    # perf_event_open システムコールの呼び出し
    my $target_pid = -1;                     # すべてのプロセスを監視
    my $cpu        = 0;                      # すべてのCPUで監視
    my $group_fd   = -1;
    my $flags      = PERF_FLAG_FD_CLOEXEC;

    my $perf_fd
        = syscall( SYS_perf_event_open, $attr, $target_pid, $cpu, $group_fd,
        $flags );
    if ( $perf_fd < 0 ) {
        my $errno     = $! + 0;
        my $error_msg = $!;
        die sprintf( "perf イベントのオープンに失敗しました: %s (errno: %d)\n",
            $error_msg, $errno );
    }

    print "perf_event_open successful. File descriptor: $perf_fd\n";

    # BPF プログラムを perf イベントにアタッチ
    $! = 0;    # reset errno
    my $res
        = syscall( &SYS_ioctl, $perf_fd, PERF_EVENT_IOC_SET_BPF, $prog_fd );
    my $errno = $! + 0;
    print "ioctl res: $res\n";
    if ( !defined $res || $res < 0 ) {
        my $error_msg = $!;
        die sprintf( "BPF プログラムのアタッチに失敗しました: %s (errno: %d)\n",
            $error_msg, $errno );
    }

    print "BPF program attached successfully\n";

    # perf イベントを有効化
    $!     = 0;    # reset errno
                   # $res = ioctl($perf_fh, PERF_EVENT_IOC_ENABLE, 0)|| -1;
    $res   = syscall( &SYS_ioctl, $perf_fd, PERF_EVENT_IOC_ENABLE, 0 );
    $errno = $! + 0;
    if ( !defined $res || $res < 0 ) {
        my $error_msg = $!;
        die sprintf( "perf イベントの有効化に失敗しました: %s (errno: %d)\n",
            $error_msg, $errno );
    }

    print "perf event enabled successfully\n";

    # デタッチ時に必要な情報を返す
    return {
        perf_fd       => $perf_fd,
        event_name    => $event_name,
        kprobe_fn     => $kprobe_fn,
        kprobe_events => $kprobe_events,
    };
}

sub check_prog_fd {
    my ($prog_fd) = @_;
    return 0 if $prog_fd < 0;

    my $flags = fcntl( $prog_fd, F_GETFL, 0 );
    return 0 if !defined $flags || $flags < 0;

    return 1;
}

sub detach_kprobe {
    my ($kprobe_info) = @_;

    my $perf_fd       = $kprobe_info->{perf_fd};
    my $event_name    = $kprobe_info->{event_name};
    my $kprobe_events = $kprobe_info->{kprobe_events};

    # perf イベントを無効化
    my $res = syscall( SYS_ioctl, $perf_fd, PERF_EVENT_IOC_DISABLE, 0 );
    if ( $res != 0 ) {
        warn "perf イベントの無効化に失敗しました: $!";
    }

    # perf イベントのファイルディスクリプタをクローズ
    close($perf_fd);

    # kprobe イベントの削除
    open my $fh, '>>', $kprobe_events or warn "kprobe_events を開けません: $!";
    $fh->autoflush(1);
    print $fh "-:$event_name\n" or warn "kprobe_events への書き込みに失敗しました: $!";
    close $fh                   or warn "kprobe_events のクローズに失敗しました: $!";
}
1;
