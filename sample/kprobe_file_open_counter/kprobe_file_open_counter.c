#include <linux/bpf.h>
#include <linux/ptrace.h>

#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

SEC("kprobe/sys_open")
int kprobe_sysopen()
{
    __u32 key = 1;
    __u64 initval = 1, *valp;

    valp = bpf_map_lookup_elem(&kprobe_map, &key);
    if (!valp)
    {
        bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
