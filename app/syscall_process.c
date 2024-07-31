//go:build ignore

#include "common.h"
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

char __license[] SEC("license") = "Dual MIT/GPL"; 

// Define the template for the inner maps (e.g., protocol counts)
struct bpf_map_def SEC("maps") inner_map_template = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),  // E.g., protocol number
    .value_size = sizeof(u64), // Count of packets
    .max_entries = 256,
};

// Define the outer map
struct bpf_map_def SEC("maps") outer_map = {
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size = sizeof(u32),  // PID
    .value_size = sizeof(u32), // Inner map id (u32 is standard)
    .max_entries = 1024,
    .map_flags = BPF_F_NO_PREALLOC,
    .inner_map_idx = 0,  // Index of the template map in the ELF file
};


SEC("tracepoint/syscalls/sys_enter")
int collect_sys_calls(struct trace_event_raw_sys_enter *ctx) {
    // Get the system call number
    int syscall_nr = ctx->id;

    // Get the process ID (PID)
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Output to the trace pipe (can be seen with `sudo cat /sys/kernel/debug/tracing/trace_pipe`)
    bpf_printk("PID %d: Syscall %d\n", pid, syscall_nr);
	
	// Get the inner map for the current PID, if it exists, otherwise create a slot for it
	u32 *inner_map_id = bpf_map_lookup_elem(&outer_map, &pid);
	if (inner_map_id == NULL) {
		// Create a new inner map
		u32 inner_map_id = 0;
		bpf_map_update_elem(&outer_map, &pid, &inner_map_id, BPF_ANY);
	}
	// Get the inner map for the current PID
	u64 *inner_map = bpf_map_lookup_elem(&inner_map_template, inner_map_id);
	// Increment the count for the current syscall
	if (inner_map != NULL) {
		u64 *count = bpf_map_lookup_elem(inner_map, &syscall_nr);
		if (count != NULL) {
			(*count)++;
		} 
		else {
			(*count) = 1;
		}
	}
	else {
		bpf_printk("Inner map not found for PID %d\n", pid);
	}


    return 0;
}