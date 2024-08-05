//go:build ignore

// #include "common.h"
#include <linux/types.h>
#include <iproute2/bpf_elf.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h> // Add this line to include the header file that defines uint64_t


// try to load the ebpf map from /sys/fs/bpf/outer_map

char __license[] SEC("license") = "Dual MIT/GPL"; 

// Define the inner map template
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
    __uint(max_entries, 100);  // Same as the Go spec
} inner_map_template SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));  // Should be u32 (map FD)
    __uint(max_entries, 5);  // Same as MaxEntries in Go code
    __array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		/* changing max_entries to 2 will fail during load
		 * due to incompatibility with inner_map definition */
		__uint(max_entries, 1);
		__type(key, int);
		__type(value, int);
	});
    
} outer_map SEC(".maps") = {
    // Initialize with the file descriptors of the inner maps (example)
    // This can be set dynamically later
    .values = {
		(void *)&inner_map_template,
			0,0,0,0
	},
};

// The correct structure for sys_enter tracepoint
struct sys_enter_args {
    uint64_t unused; // First argument is not used
    uint64_t syscall_nr; // This is the syscall number
    uint64_t args[6]; // Array of arguments to the syscall
};

SEC("tracepoint/syscalls/sys_enter")
// int collect_sys_calls(struct trace_event_raw_sys_enter *ctx) {
int collect_sys_calls(struct sys_enter_args *ctx) {
	uint32_t key = 0;
	uint32_t *inner_map_idx = bpf_map_lookup_elem(&outer_map, &key);
	if (!inner_map_idx) {
		return 0;
	}

	struct bpf_map *inner_map = bpf_map_lookup_elem(&outer_map, inner_map_idx);
	if (!inner_map) {
		return 0;
	}
	
	uint64_t syscall_nr = ctx->syscall_nr;
	uint64_t *value = bpf_map_lookup_elem((void *)(inner_map), &syscall_nr);
    if (!value) {
        return 0;
    }

	(*value)++;
	return 0;
	
}