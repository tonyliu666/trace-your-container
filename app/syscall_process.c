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
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 5000);
	__type(key, sizeof(uint32_t));
	__type(value, sizeof(uint32_t));
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);  // Outer map type
    __uint(key_size, sizeof(uint32_t));       // Key size of the outer map
	__uint(max_entries, 1000); 
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
    u32 key = 0;
    uint32_t pid = (uint32_t)bpf_get_current_pid_tgid() >> 32;
   long int syscall_id = (long int)ctx[1];
   struct pt_regs *regs = (struct pt_regs *)ctx[0];
    struct inner_map *inner_map = bpf_map_lookup_elem(&outer_map, &key);

   bpf_printk("inner map size: %d\n", sizeof(inner_map));
   if (inner_map == NULL) {
       bpf_printk("inner map is NULL\n");
       return 0;
   }
   else{
        // insert the syscall_id into the inner map and the count of the syscall_id
        uint32_t syscall_id_key = (uint32_t)syscall_id;
        // uint32_t *count = bpf_map_lookup_elem(&inner_map, &syscall_id_key);
        // if (count == NULL) {
        //     uint32_t count = 1;
        //     bpf_map_update_elem(&inner_map, &syscall_id_key, &count, BPF_ANY);
        // } else {
        //     (*count)++;
        // }
        // bpf_printk("pid: %d, syscall_id: %ld\n, system call count: %u\n", pid, syscall_id, *count);
        bpf_printk("pid: %d, syscall_id: %ld\n", pid, syscall_id);
    }
    
	return 0;
}
