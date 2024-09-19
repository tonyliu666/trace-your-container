//go:build ignore
// #include <linux/bpf.h>
// #include <linux/types.h>
# include "common.h"
#include <bpf_helpers.h>
  // For task_struct and process-related functions
#include <bpf/bpf_core_read.h>
#include "vmlinux.h"

// try to load the ebpf map from /sys/fs/bpf/outer_map

char __license[] SEC("license") = "Dual MIT/GPL"; 

struct inner_map{
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 47069); // TODO: fix hard-coded value
	__type(key, u32);
	__type(value, u32);
} inner_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);  // Outer map type
    __type(key, u32);       // Key size of the outer map
	__uint(max_entries, 1024); 
    __array(values, struct inner_map);
} outer_map SEC(".maps");


SEC("raw_tracepoint/cgroup_mkdir")
int on_cgroup_create(__u64 *ctx) {
    char cgroup_path[128];
    const char *path = (const char *) ctx[1];
    const char *compare_path = "/system.slice/docker";

    u64 cgroup_id = ctx[0]; 
    
    bpf_probe_read_str(cgroup_path, sizeof(cgroup_path), path);
    
    // Copy the cgroup path from the event context
    
    if (bpf_strncmp(cgroup_path,(u32)20, compare_path) == 0) {
        // TODO: update the outer map
    }

    return 0;
}

// SEC("tp_btf/sys_enter")
SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(__u64 *ctx) {
    u32 key;
    u32 pid = (u32)bpf_get_current_pid_tgid();
    u32 syscall_id = (u32)ctx[1];

    // Check if the process is in a Docker container
    // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 cgroup_id = bpf_get_current_cgroup_id();
    bpf_printk("pid: %d\n", pid);
    bpf_printk("cgroup_id: %ld\n", cgroup_id);
 
    struct pt_regs *regs = (struct pt_regs *)ctx[0];
    void *inner_map = bpf_map_lookup_elem(&outer_map, &pid);

    if (inner_map == NULL) {
        // bpf_printk("inner_map is NULL\n");
       return 0;
    }

   else{
        bpf_printk("syscall_id_key: %ld\n", syscall_id);
        // insert the syscall_id into the inner map and the count of the syscall_id
        u32 syscall_id_key = syscall_id;
        
        u32 *count = bpf_map_lookup_elem(inner_map, &syscall_id_key);
        if (count == NULL) {
            u32 count = 1;
            bpf_map_update_elem(inner_map, &syscall_id_key, &count, BPF_ANY);
        } else {
            (*count)++;
        }
        
    }
    
	return 0;
}
