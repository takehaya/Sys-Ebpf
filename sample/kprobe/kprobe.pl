#!/usr/bin/env perl

use strict;
use warnings;
use lib '../../lib';  # lib ディレクトリへの相対パスを追加
use ebpf::loader;
use Data::Dumper;

use ebpf::constants::bpf_map_type qw(BPF_MAP_TYPE_ARRAY);

my $file = "kprobe.o";
my $loader = ebpf::loader->new($file);
my $data = $loader->load_elf();

my($map_data, $prog_fd)=$loader -> load_bpf("kprobe/sys_execve");


# # Kprobeをアタッチ
# my $kprobe_info = $loader->attach_kprobe($prog_fd, $fn);

# print "Waiting for events..\n";

# # 1秒ごとにマップの値を読み取り、表示
# while (1) {
#     my $value = $map->lookup(pack('L', 0));
#     if (defined $value) {
#         my $count = unpack('Q', $value);
#         printf "%s called %d times\n", $fn, $count;
#     } else {
#         warn "Failed to read map value\n";
#     }
#     sleep(1);
# }

# # クリーンアップ（この部分は実際には実行されませんが、適切な終了処理のために必要です）
# END {
#     if ($loader && $kprobe_info) {
#         $loader->detach_kprobe($kprobe_info);
#     }
# }

# いろいろな出力方法があるっぽい
# print Dumper($data);
# print "magic: $data->{magic}, $data->{class}\n";
# while (my ($key, $value) = each %$data) {
#     print "$key: $value\n";
# }