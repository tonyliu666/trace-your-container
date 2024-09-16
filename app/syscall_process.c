//go:build ignore

#include "common.h"
#include <linux/types.h>
#include <iproute2/bpf_elf.h>
// #include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
// #include "bpf_helpers.h"
#include <stdint.h> // Add this line to include the header file that defines uint64_t

// #include "bpf_tracing.h"

// try to load the ebpf map from /sys/fs/bpf/outer_map

char __license[] SEC("license") = "Dual MIT/GPL"; 

struct inner_map{
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 5000);
	__type(key, uint32_t);
	__type(value, uint32_t);
} inner_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);  // Outer map type
    __type(key, uint32_t);       // Key size of the outer map
	__uint(max_entries, 1000); 
    __array(values, struct inner_map);
} outer_map SEC(".maps");

    
// The correct structure for sys_enter tracepoint
struct sys_enter_args {
    uint64_t unused; // First argument is not used
    uint64_t syscall_nr; // This is the syscall number
    uint64_t args[6]; // Array of arguments to the syscall
};


// SEC("tp_btf/sys_enter")
SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(u64 *ctx) {
    uint32_t key = 0;
    uint32_t pid = (uint32_t)bpf_get_current_pid_tgid();
    long int syscall_id = (long int)ctx[1];
    struct pt_regs *regs = (struct pt_regs *)ctx[0];
    void *inner_map = bpf_map_lookup_elem(&outer_map, &pid);

   
    if (inner_map == NULL) {
        // bpf_printk("process id: %u\n", pid);
        // bpf_printk("syscall_id: %ld\n", syscall_id);
        // bpf_printk("inner map is NULL\n");
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
