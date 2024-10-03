#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_FILENAME_LEN 128
#define MAX_ENTRIES 1024

struct file_open_info
{
    __u32 count;
    char filename[MAX_FILENAME_LEN];
};

struct bpf_map_def SEC("maps") file_open_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct file_open_info),
    .max_entries = MAX_ENTRIES,
};

SEC("kprobe/sys_open")
int kprobe_sys_open(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // __userを削除
    const char *filename_ptr = (const char *)PT_REGS_PARM1(ctx);
    char filename[MAX_FILENAME_LEN];
    int ret = bpf_probe_read_kernel_str(filename, sizeof(filename), filename_ptr);
    if (ret < 0)
    {
        bpf_printk("bpf_probe_read_user_str failed: %d\n", ret);
        return 0;
    }
    bpf_printk("filename: %s\n", filename);
    struct file_open_info info = {};
    struct file_open_info *pinfo;

    pinfo = bpf_map_lookup_elem(&file_open_map, &pid);
    if (pinfo)
    {
        // 既存のエントリがある場合はカウントを増加
        info.count = pinfo->count + 1;
    }
    else
    {
        // 新しいエントリの場合はカウントを1に設定
        info.count = 1;
    }

    // ファイル名をコピー
    __builtin_memcpy(&info.filename, filename, sizeof(info.filename));
    bpf_printk("pid: %d\n", pid);
    // bpf_printk("filename: %s\n", info.filename);
    // マップを更新
    bpf_map_update_elem(&file_open_map, &pid, &info, BPF_ANY);

    return 0;
}
