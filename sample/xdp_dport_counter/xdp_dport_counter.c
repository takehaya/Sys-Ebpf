#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") xdp_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

SEC("xdp/xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *value;

    value = bpf_map_lookup_elem(&xdp_map, &key);
    if (value)
    {
        __sync_fetch_and_add(value, 1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
