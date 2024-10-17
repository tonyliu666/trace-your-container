package cgroup

import (
	"docker_cgroup/util"
	"log"
	"strconv"

	"github.com/cilium/ebpf"
)

func InsertEntryToInnerMap(cgroupInodeNum uint32) error {
	innerMapSpec := CreateInnerMapSpec(uint64(cgroupInodeNum))
	innerMap, err := ebpf.NewMap(&innerMapSpec)
	if err != nil {
		log.Fatalf("inner_map: %v", err)
		return err
	}

	maps := util.EbpfCollection.Maps["outer_map"]

	// if err := util.OuterMap.Put(uint32(cgroupInodeNum), innerMap); err != nil {
	if err := maps.Update(uint32(cgroupInodeNum), uint32(innerMap.FD()), ebpf.UpdateAny); err != nil {
		log.Fatalf("outerMap.Update: %v", err)
		return err
	}
	return nil
}
func CreateInnerMapSpec(pid uint64) ebpf.MapSpec {
	fill_portion := ""
	if pid != 0 {
		fill_portion = strconv.Itoa(int(pid))
	}

	innerMapSpec := ebpf.MapSpec{
		Name:       "inner_map" + fill_portion,
		Type:       ebpf.Hash,                                 // Type changed to Array to match BPF_MAP_TYPE_ARRAY
		KeySize:    4,                                         // Size of keys in the inner map (uint32_t)
		ValueSize:  4,                                         // Size of values in the inner map (uint32_t)
		MaxEntries: uint32(util.MaxMumProcessSizeInContainer), // Maximum number of entries in the inner map
	}
	return innerMapSpec
}
