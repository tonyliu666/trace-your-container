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


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} cgroup_events SEC(".maps");

SEC("raw_tracepoint/cgroup_mkdir")
int on_cgroup_create(__u64 *ctx) {
    char cgroup_path[128];
    const char *path = (const char *) ctx[1];
    const char *compare_path = "/system.slice/docker";

    u32 cgroup_id = (u32)ctx[0]; 
    
    bpf_probe_read_str(cgroup_path, sizeof(cgroup_path), path);
    u32 cpu = bpf_get_smp_processor_id();
    
    // Copy the cgroup path from the event context
    bpf_printk("cpu: %d\n", cpu);
    
    if (bpf_strncmp(cgroup_path,(u32)20, compare_path) == 0) {
        // TODO: create an entry in the outer map
        // bpf_perf_event_output(ctx, &cgroup_events, BPF_F_CURRENT_CPU, &cgroup_id, sizeof(cgroup_id));
        bpf_printk("ready to send cgroup id to perf event array\n");
        
        int ret = bpf_perf_event_output(ctx, &cgroup_events, BPF_F_CURRENT_CPU, &cgroup_id, sizeof(cgroup_id));
        if (ret == -2) {
            bpf_printk("Error sending to perf event buffer: %d\n", ret);
        }
        bpf_printk("send cgroup id to perf event array\n");
    }

    return 0;
}

// SEC("tp_btf/sys_enter")
SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(__u64 *ctx) {
    u32 key;
    u32 pid = (u32)bpf_get_current_pid_tgid();
    u32 syscallID = (u32)ctx[1];

    // Check if the process is in a Docker container
    // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 cgroupId = (u32)bpf_get_current_cgroup_id();
    void *inner_map = bpf_map_lookup_elem(&outer_map, &cgroupId);

    if (inner_map == NULL) {
       return 0;
    }

   else{
        bpf_printk("syscallID_key: %ld\n", syscallID);
        // insert the syscallID into the inner map and the count of the syscallID
        u32 syscallID_key = syscallID;
        
        u32 *count = bpf_map_lookup_elem(inner_map, &syscallID_key);
        if (count == NULL) {
            u32 count = 1;
            bpf_map_update_elem(inner_map, &syscallID_key, &count, BPF_ANY);
        } else {
            (*count)++;
        }
        
    }
    
	return 0;
}
