package cgroup

import (
	"docker_cgroup/util"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type BPFCgroupNetworkDirection struct {
	Name       string
	AttachType ebpf.AttachType
	FilePath   string
}

var BPFCgroupNetworkDirections = []BPFCgroupNetworkDirection{}

func AttachBPFCgroupNetworkDirections() {
	for _, direction := range BPFCgroupNetworkDirections {

		link, err := link.AttachCgroup(link.CgroupOptions{
			Path:    direction.FilePath,
			Attach:  direction.AttachType,
			Program: util.EbpfCollection.Programs[direction.Name],
		})
		if err != nil {
			log.Fatal(err)
		}
		util.TracepointMaps[direction.FilePath+direction.Name] = link
	}

}

func InsertEntryToIngressHashMap(cgroupID uint32) error {
	value := uint32(0)
	err := util.EbpfCollection.Maps["cgroup_ingress_map"].Update(&cgroupID, &value, 0)
	if err != nil {
		return err
	}
	return nil
}
func InsertEntryToEgressHashMap(cgroupID uint32) error {
	value := uint32(0)
	err := util.EbpfCollection.Maps["cgroup_egress_map"].Update(&cgroupID, &value, 0)
	if err != nil {
		return err
	}
	return nil
}

func DeleteEntryFromIngressHashMap(cgroupID uint32) error {
	err := util.EbpfCollection.Maps["cgroup_ingress_map"].Delete(&cgroupID)
	if err != nil {
		return err
	}
	return nil
}

func DeleteEntryFromEgressHashMap(cgroupID uint32) error {
	err := util.EbpfCollection.Maps["cgroup_egress_map"].Delete(&cgroupID)
	if err != nil {
		return err
	}
	return nil
}
