package main

import (
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"

	cgroups "github.com/containerd/cgroups"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go syscall syscall_process.c -- -I../headers
func readFileName(dirname string) ([]string, error) {
	dir, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	// Read all the files in the directory
	files, err := dir.Readdirnames(0) // 0 to read all files and directories
	if err != nil {
		return nil, err
	}
	return files, nil
}
func init(){
	
}


func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// create hash of maps initially without any inner maps
	outerMapSpec := ebpf.MapSpec{
		Name:       "outer_map",
		Type:       ebpf.HashOfMaps,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1000, // We'll have 5 maps inside this map
	}
	innerMapSpec := ebpf.MapSpec{
		Name:       "inner_map",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 5000,
	}
	outerMapSpec.InnerMap = &innerMapSpec

	// All inner maps are created and inserted into the outer map spec,
	outerMap, err := ebpf.NewMap(&outerMapSpec)
	if err != nil {
		log.Fatalf("outer_map: %v", err)
	}
	defer outerMap.Close()

	// Pin the outer map
	if err := outerMap.Pin("/sys/fs/bpf/outer_map"); err != nil {
		if _, ok := err.(*os.PathError); !ok {
			log.Fatalf("pinning outer_map: %v", err)
		}
	}

	objs := syscallObjects{}
	if err := loadSyscallObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	objs.syscallMaps.OuterMap = outerMap

	tp, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.BtfRawTracepointSysEnter,
		AttachType: ebpf.AttachTraceRawTp,
	})

	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	files, err := readFileName("/sys/fs/cgroup/systemd")
	if err != nil {
		log.Fatal(err)
	}

	var cgroupV2 bool
	cgroupList := []cgroups.Cgroup{}

	if cgroups.Mode() == cgroups.Unified {
		cgroupV2 = true
	}
	log.Infof("cgroupV2: %v", cgroupV2)

	if !cgroupV2 {
		containerProcess := []cgroups.Process{}
		for _, cgroupPath := range files {
			if len(cgroupPath) == 64 {
				cg, err := cgroups.Load(cgroups.Systemd, cgroups.StaticPath("/docker/"+cgroupPath))
				if err != nil {
					log.Fatal(err)
				}
				cgroupList = append(cgroupList, cg)
			}
		}
		// print the cgroup status in cgroupList
		for _, cg := range cgroupList {
			for _, subsys := range cg.Subsystems() {
				processes, _ := cg.Tasks(subsys.Name(), true)
				containerProcess = append(containerProcess, processes...)
			}
		}
		for _, process := range containerProcess {
			// if process id not exists in the map, insert it
			if err := outerMap.Put(uint32(process.Pid), uint32(0)); err != nil {
				log.Fatalf("inserting process id: %v", err)
			}
		}

	}
}
