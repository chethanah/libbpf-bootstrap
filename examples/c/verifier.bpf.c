// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 18984;

/* Verify CONFIG_CGROUP_BPF
    Ref: https://docs.kernel.org/bpf/map_cgroup_storage.html 
    BPF_MAP_TYPE_CGROUP_STORAGE map type is only available with CONFIG_CGROUP_BPF
*/
struct {
        __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
        __type(key, struct bpf_cgroup_storage_key);
        __type(value, __u32);
} cgroup_storage SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

    bpf_printk("BPF triggered from PID %d.\n", pid);
    
	return 0;
}

SEC("cgroup_skb")
int program(struct __sk_buff *skb)
{
    __u32 *ptr = bpf_get_local_storage(&cgroup_storage, 0);
    __sync_fetch_and_add(ptr, 1);
    bpf_printk("ptr=%d.\n", &ptr);
    return 0;
}
