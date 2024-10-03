#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct bpf_map_def SEC("maps") xdp_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

SEC("xdp/xdp_count_8080_port")
int xdp_count_8080_port(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 key = 0;
    __u64 *value;

    // Ethernetヘッダのサイズ確認
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    // IPヘッダの確認
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    // TCPパケットかどうかを確認
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // TCPヘッダの確認
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    // 目的ポートが8080かどうか確認
    if (tcp->dest == bpf_htons(8080))
    {
        value = bpf_map_lookup_elem(&xdp_map, &key);
        if (value)
        {
            __sync_fetch_and_add(value, 1);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
