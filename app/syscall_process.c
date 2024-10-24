//go:build ignore
// #include <linux/bpf.h>
// #include <linux/types.h>
#define __TARGET_ARCH_x86
#define MAX_PATH_LEN 64
#define LIMIT_PATH_LEN(x) ((x) & (MAX_PATH_LEN - 1))
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

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} container_events SEC(".maps");

struct event {
    u32 cgroupID; 
};
struct path_event {
    char path[MAX_PATH_LEN];
    int offsets;
};


SEC("raw_tracepoint/cgroup_mkdir")
int on_cgroup_create(struct bpf_raw_tracepoint_args *ctx) {
    char cgroup_path[128];
    const char *path = (const char *) ctx->args[1];
    const char *compare_path = "/system.slice/docker";
    u64 cgroup_id;

    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    struct kernfs_node *kn = BPF_CORE_READ(dst_cgrp, kn);
    // kernel v5.5 and above
    bpf_core_read(&cgroup_id, sizeof(u64), &kn->id);
    
    bpf_probe_read_str(cgroup_path, sizeof(cgroup_path), path);
    
    if (bpf_strncmp(cgroup_path,(u32)20, compare_path) == 0) {
        // TODO: create an entry in the outer map
        struct event cgroup_event = {cgroup_id};
        // bpf_printk("cgroup created: %s, cgroup id: %d\n", cgroup_path, cgroup_id);
        
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


SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter *ctx){
    u32 key;
    u32 pid = (u32)bpf_get_current_pid_tgid();

    // Check if the process is in a Docker container
    u32 cgroupId = (u32)bpf_get_current_cgroup_id();
    // TODO: cannot find the inner map
    struct bpf_map* inner_map = bpf_map_lookup_elem(&outer_map, &cgroupId);

    char filename[128];
    
    // Read the first argument to the open syscall, which is the filename
    bpf_probe_read_user_str(&filename, sizeof(filename), (void *)ctx->args[0]);
    
    if (!inner_map) {
       return 0;
    }

   else{
        bpf_printk("Opening file: %s, cgroupId: %d", filename, cgroupId);
        u32 syscallID_key = 2;
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

SEC("tracepoint/syscalls/sys_enter_unlink")
int sysEnterUnlink(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 cgroupId = (u32)bpf_get_current_cgroup_id();

    struct bpf_map* inner_map = bpf_map_lookup_elem(&outer_map, &cgroupId);
    if (!inner_map) {
        return 0;
    }
    
    char filename[32];
    struct fs_struct *fs = BPF_CORE_READ(task, fs);
    struct path pwd = BPF_CORE_READ(fs, pwd);
    struct dentry *dentry = pwd.dentry;
    struct qstr d_name;
    u32 name_len = 0;

    // Buffer for constructing the full path
    bpf_probe_read_user_str(&filename, sizeof(filename), (void *)ctx->args[0]);
    int buf_offset = MAX_PATH_LEN;

    struct path_event event = {};
    event.offsets = buf_offset;
    // get the length of the filename
    bpf_probe_read_kernel(&name_len, sizeof(name_len), &dentry->d_name.len);

    event.offsets = LIMIT_PATH_LEN(event.offsets - name_len-1);
    bpf_probe_read_str(&event.path[event.offsets], LIMIT_PATH_LEN(name_len+1), filename);

    
    #pragma unroll
    for (int i = 0; i < 40; i++) {  // Limit traversal to 20 levels
        struct dentry *parent_dentry = BPF_CORE_READ(dentry, d_parent);
        if (dentry == parent_dentry) {
            break;  // Stop if root is reached
        }
        
        d_name = BPF_CORE_READ(dentry, d_name);
        bpf_probe_read_kernel(&name_len, sizeof(name_len), &d_name.len);
        
        // Reduce buffer offset and ensure it's within valid bounds
        event.offsets = LIMIT_PATH_LEN(event.offsets - name_len-1);  // Account for '/' and name_len
        if (event.offsets < 0) {
            bpf_printk("path too long\n");
            break;
        }

        // Copy the directory name into the path buffer
        bpf_probe_read_str(&event.path[event.offsets], LIMIT_PATH_LEN(name_len+1), d_name.name);
        int front_offset = LIMIT_PATH_LEN(event.offsets-1);
        int back_offset = LIMIT_PATH_LEN(event.offsets + name_len);
        event.path[front_offset] = '/';  // Add '/' before the directory name
        event.path[back_offset] = '/';  // Null-terminate the string
        
        // Move to the parent directory
        dentry = parent_dentry;
    }
    event.offsets = LIMIT_PATH_LEN(event.offsets);
    // Print the final constructed path without the null terminator
    bpf_printk("Unlinking file: %s\n", event.path+event.offsets);

    return 0;

}



SEC("tp_btf/sys_enter")
int sysEnter(struct trace_event_raw_sys_enter *ctx) {
    // Access system call arguments or system call ID using `id` or `regs`
    u32 key;
    u32 pid = (u32)bpf_get_current_pid_tgid();
    long int syscall_id = ctx->id;
    if (syscall_id == 2){
        return 0;
    }
    
    u32 cgroupId = (u32)bpf_get_current_cgroup_id();
    
    struct bpf_map* inner_map = bpf_map_lookup_elem(&outer_map, &cgroupId);
    if (!inner_map) {
       return 0;
    }
    else{
        // bpf_printk("process %d in cgroup %d call system call id %ld\n", pid, cgroupId, syscall_id);
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
    struct task_struct *task;
    char buf[128];
    struct path p;
    struct mm_struct *mm;
    struct file *exe_file;
    struct f_path *f_path;
    task = (struct task_struct *)bpf_get_current_task();
   
    p = BPF_CORE_READ(task, mm, exe_file, f_path);
    u64 cgroup_id = bpf_get_current_cgroup_id();
    // bpf_printk("Cgroup ID: %llu\n", cgroup_id);
    //bpf_probe_read_str(buf, sizeof(buf), p.dentry->d_iname);
    
    // pid_t pid = BPF_CORE_READ(task, pid);
    pid_t pid;
    bpf_probe_read(&pid, sizeof(pid), &task->pid);
    //bpf_printk(" pid: %d\n", buf, pid);
    // get the parent folder name
    struct dentry *parent_dentry = BPF_CORE_READ(p.dentry, d_parent);
    bpf_probe_read_str(buf, sizeof(buf), parent_dentry->d_iname);
    // bpf_printk("parent folder name: %s\n", buf);
    return 0;
}