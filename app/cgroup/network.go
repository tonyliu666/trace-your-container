package cgroup

import (
	"docker_cgroup/util"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type BPFCgroupNetworkDirection struct {
	Name       string
	AttachType ebpf.AttachType
	FilePath   string
}
type BpfCgroupStorageKey struct {
	CgroupInodeId uint64
	AttachType    ebpf.AttachType
}
type perCPUCounters []uint64

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
		defer link.Close()
	}

}

func sumPerCpuCounters(perCpuCounters perCPUCounters) uint64 {
	sum := uint64(0)
	for _, counter := range perCpuCounters {
		sum += counter
	}
	return sum
}
func NetworkPacketCount() {
	// Wait until signaled
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT)
	signal.Notify(c, syscall.SIGTERM)

	// Periodically check counters
	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-ticker.C:
			log.Println("-------------------------------------------------------------")

			for cgroupInodeId, _ := range util.ProcessIDMaps {
				for _, direction := range BPFCgroupNetworkDirections {
					var perCPUCounters perCPUCounters

					mapKey := BpfCgroupStorageKey{
						CgroupInodeId: cgroupInodeId,
						AttachType:    direction.AttachType,
					}

					if err := util.CgroupNetworkMap.Lookup(mapKey, &perCPUCounters); err != nil {
						log.Printf("%s: error reading map (%v)", direction.Name, err)
					} else {
						log.Printf("%s: %d\n", direction.Name, sumPerCpuCounters(perCPUCounters))
					}
				}
			}
		case <-c:
			log.Println("Exiting...")
			break
		}
	}

}
