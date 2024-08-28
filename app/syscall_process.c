//go:build ignore

#include "common.h"
#include <linux/types.h>
#include <iproute2/bpf_elf.h>
// #include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h> // Add this line to include the header file that defines uint64_t
#include <bpf/bpf_tracing.h>

// try to load the ebpf map from /sys/fs/bpf/outer_map

char __license[] SEC("license") = "Dual MIT/GPL"; 

struct inner_map{
    __uint(type, BPF_MAP_TYPE_HASH);          // Inner map type
    __uint(key_size, sizeof(uint32_t));       // Key size of the inner map
    __uint(value_size, sizeof(uint32_t));     // Value size of the inner map
    __uint(max_entries, 50);                  // Max entries in the inner map, must match Go code
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);  // Outer map type
    __uint(key_size, sizeof(uint32_t));       // Key size of the outer map
	__uint(max_entries, 1); 
    __array(values, struct inner_map);
} outer_map SEC(".maps");

    
// The correct structure for sys_enter tracepoint
struct sys_enter_args {
    uint64_t unused; // First argument is not used
    uint64_t syscall_nr; // This is the syscall number
    uint64_t args[6]; // Array of arguments to the syscall
};

SEC("tp_btf/sys_enter")
int btf_raw_tracepoint__sys_enter(u64 *ctx) {
   long int syscall_id = (long int)ctx[1];
   struct pt_regs *regs = (struct pt_regs *)ctx[0];
   	// fetch the outer map
	// struct bpf_map *outer_map = bpf_map_lookup_elem(&outer_map, &syscall_id);
	bpf_printk("syscall_id: %d\n", syscall_id);
	return 0;
}
