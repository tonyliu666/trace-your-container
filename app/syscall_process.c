//go:build ignore

#include "common.h"
#include <linux/types.h>
// #include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <stdint.h> // Add this line to include the header file that defines uint64_t
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
// #include <bpf/bpf.h>
// #include "bpf_tracing.h"

// try to load the ebpf map from /sys/fs/bpf/outer_map

char __license[] SEC("license") = "Dual MIT/GPL"; 

struct inner_map{
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 47069); // TODO: fix hard-coded value
	__type(key, uint32_t);
	__type(value, uint32_t);
} inner_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);  // Outer map type
    __type(key, uint32_t);       // Key size of the outer map
	__uint(max_entries, 1024); 
    __array(values, struct inner_map);
} outer_map SEC(".maps");


#define MAX_LINE_LEN 256

// Function to check if the process is in a Docker container
int checkProcessIsInDocker(uint32_t pid) {
    char proc_path[MAX_LINE_LEN];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cgroup", pid);

    FILE *file = fopen(proc_path, "r");
    if (!file) {
        perror("Failed to open cgroup file");
        return false;
    }

    char line[MAX_LINE_LEN];
    bool is_docker = false;
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "docker-")) {  // Check for Docker cgroup pattern
            is_docker = true;
            break;
        }
    }

    fclose(file);
    return is_docker;
}
   

// SEC("tp_btf/sys_enter")
SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(uint64_t *ctx) {
    uint32_t key;
    uint32_t pid = (uint32_t)bpf_get_current_pid_tgid();

    // Check if the process is in a Docker container
    if (!checkProcessIsInDocker(pid)) {   
        return 0;
    }
    bpf_printk("pid: %d\n", pid);
 
    long int syscall_id = (long int)ctx[1];
    struct pt_regs *regs = (struct pt_regs *)ctx[0];
    void *inner_map = bpf_map_lookup_elem(&outer_map, &pid);

    if (inner_map == NULL) {
        bpf_printk("inner_map is NULL\n");
       return 0;
    }

   else{
        bpf_printk("syscall_id_key: %ld\n", syscall_id);
        // insert the syscall_id into the inner map and the count of the syscall_id
        uint32_t syscall_id_key = (uint32_t)syscall_id;
        
        uint32_t *count = bpf_map_lookup_elem(inner_map, &syscall_id_key);
        if (count == NULL) {
            uint32_t count = 1;
            bpf_map_update_elem(inner_map, &syscall_id_key, &count, BPF_ANY);
        } else {
            (*count)++;
        }
        
    }
    
	return 0;
}
