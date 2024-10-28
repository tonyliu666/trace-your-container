package cgroup

import (
	"docker_cgroup/util"
	"log"

	ebpf "github.com/cilium/ebpf"
)

// create a map corresponding to the cgroup in c:

// struct{
//     __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
//     __type(key, struct bpf_cgroup_storage_key);
//     __type(value, __u64);
// } cgroup_network_map SEC("maps");

func CreateCgroupMap() error {
	cgroupNetworkMapSpec := &ebpf.MapSpec{
		Type:       ebpf.PerCPUCGroupStorage, // BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
		KeySize:    12,                       // sizeof(struct bpf_cgroup_storage_key)
		ValueSize:  8,                        // sizeof(__u64)
		MaxEntries: 1,                        // Should be zero for this map type
	}
	cgroupNetworkMap, err := ebpf.NewMap(cgroupNetworkMapSpec)
	if err != nil {
		log.Fatalf("failed to create cgroup network map: %v", err)
	}
	util.CgroupNetworkMap = cgroupNetworkMap
	if err := util.CgroupNetworkMap.Pin("/sys/fs/bpf/cgroup_network_map"); err != nil {
		return err
	}
	return nil
}
