/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Reference: https://github.com/libbpf/libbpf-bootstrap*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

typedef unsigned int u32;
typedef int pid_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Create an array with 1 entry instead of a global variable
 * which does not work with older kernels */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	// Key is an index in array and can only be 4 bytes (32-bit).
	__type(key, u32);
	__type(value, u64);
} dummy_map SEC(".maps");

SEC("cgroup_skb/egress")
int handle_tp(struct __sk_buff *skb)
{
	__u32 key = 1;
	__u64 *count = bpf_map_lookup_elem(&dummy_map, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
	return 1;
}

