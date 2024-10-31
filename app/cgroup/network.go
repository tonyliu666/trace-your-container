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
