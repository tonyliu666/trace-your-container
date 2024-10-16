//go:build ignore
// #include <linux/bpf.h>
// #include <linux/types.h>
# include "common.h"
#include <bpf/bpf_helpers.h>
  // For task_struct and process-related functions
#include <bpf/bpf_tracing.h>
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

struct event {
    u32 cgroupID; 
};

SEC("raw_tracepoint/cgroup_mkdir")
int on_cgroup_create(__u64 *ctx) {
    char cgroup_path[128];
    const char *path = (const char *) ctx[1];
    const char *compare_path = "/system.slice/docker";

    u32 cgroup_id = (u32)ctx[0]; 
    
    bpf_probe_read_str(cgroup_path, sizeof(cgroup_path), path);
    
    if (bpf_strncmp(cgroup_path,(u32)20, compare_path) == 0) {
        // TODO: create an entry in the outer map
        struct event cgroup_event = {cgroup_id};
        
        int ret = bpf_perf_event_output(ctx, &cgroup_events, BPF_F_CURRENT_CPU, &cgroup_event, sizeof(cgroup_event));
        if (ret == -2) {
            bpf_printk("Error sending to perf event buffer: %d\n", ret);
        }
        else if(ret == 0){
            bpf_printk("send cgroup id to perf event array\n");
        }
        
    }

    return 0;
}

// SEC("tp_btf/sys_enter")
SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter *ctx){
    u32 key;
    u32 pid = (u32)bpf_get_current_pid_tgid();
    long int syscall_id = ctx->id;

    // Check if the process is in a Docker container
    u32 cgroupId = (u32)bpf_get_current_cgroup_id();
    // TODO: cannot find the inner map
    struct bpf_map* inner_map = bpf_map_lookup_elem(&outer_map, &cgroupId);

    char filename[128];
    
    // Read the first argument to the open syscall, which is the filename
    bpf_probe_read_user_str(&filename, sizeof(filename), (void *)ctx->args[0]);
    
    // Print the filename being opened
    bpf_printk("Opening file: %s, cgroupId: %d", filename, cgroupId);

    if (!inner_map) {
       return 0;
    }

   else{
        bpf_printk("syscallID_key: %ld\n", syscall_id);
        // insert the syscallID into the inner map and the count of the syscallID
        u32 syscallID_key = syscall_id;
        
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
SEC("tp_btf/sys_enter")
int sysEnter(struct trace_event_raw_sys_enter *ctx) {
    // Access system call arguments or system call ID using `id` or `regs`
    u32 key;
    u32 pid = (u32)bpf_get_current_pid_tgid();
    long int syscall_id = ctx->id;
    u32 cgroupId = (u32)bpf_get_current_cgroup_id();
    struct bpf_map* inner_map = bpf_map_lookup_elem(&outer_map, &cgroupId);
    if (!inner_map) {
       return 0;
    }
    else{
        bpf_printk("process %d in cgroup %d call system call id %ld\n", pid, cgroupId, syscall_id);
        // insert the syscallID into the inner map and the count of the syscallID
        u32 syscallID_key = (u32)syscall_id;
        
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


SEC("kprobe/do_unlinkat")
int unlinkAt(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u32 cgroupId = (u32)bpf_get_current_cgroup_id();
    if (cgroupId == (u32)14890) {
        bpf_printk("unlinkat syscall from process %d in cgroup %d\n", pid, cgroupId);
    }
    // bpf_printk("unlinkat syscall from process %d in cgroup %d\n", pid, cgroupId);
    return 0;
}
 