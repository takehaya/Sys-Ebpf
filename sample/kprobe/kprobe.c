#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
};
// struct {
// 	 __uint(type, BPF_MAP_TYPE_ARRAY);
// 	 __type(key, __u32);
// 	 __type(value, __u64);
// 	 __uint(max_entries, 1);
// } kprobe_map SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve()
{
	bpf_printk("Hello, BPF World!\n");
	__u32 key = 0;
	__u64 initval = 1, *valp = 0;

	valp = bpf_map_lookup_elem(&kprobe_map, &key);
	if (!valp)
	{
		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);

	return 0;
}