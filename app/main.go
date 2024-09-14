package main

import (
	"os"
	// "strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
	

	cgroups "github.com/containerd/cgroups"
)

var outerMap *ebpf.Map

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go syscall syscall_process.c -- -I../headers -target bpf
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
func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	/// Create the outer map spec for Hash of Maps
	outerMapSpec := ebpf.MapSpec{
		Name:       "outer_map",
		Type:       ebpf.HashOfMaps, // Type matches BPF_MAP_TYPE_HASH_OF_MAPS
		KeySize:    4,               // Size of keys in the outer map (uint32_t)
		ValueSize:  4,               // Size of each value (fd of inner map)
		MaxEntries: 1000,            // Maximum number of entries (keys) in the outer map
	}

	// Create the inner map spec for Array type
	innerMapSpec := ebpf.MapSpec{
		Name:       "inner_map",
		Type:       ebpf.Hash, // Type changed to Array to match BPF_MAP_TYPE_ARRAY
		KeySize:    4,         // Size of keys in the inner map (uint32_t)
		ValueSize:  4,         // Size of values in the inner map (uint32_t)
		MaxEntries: 5000,      // Maximum number of entries in the inner map
	}
	outerMapSpec.InnerMap = &innerMapSpec

	// All inner maps are created and inserted into the outer map spec,
	outer_map, err := ebpf.NewMap(&outerMapSpec)
	if err != nil {
		log.Fatalf("outer_map: %v", err)
	}
	outerMap = outer_map

	// Pin the outer map
	if err := outerMap.Pin("/sys/fs/bpf/outer_map"); err != nil {
		if _, ok := err.(*os.PathError); !ok {
			log.Info("outer_map already exists")
		}
	}
}

// create process id maps
var processIDMaps = map[int]bool{}

func main() {
	// pin the syscall_bpfeb.o to /sys/fs/bpf/syscall_bpfeb
	objs := syscallObjects{}
	if err := loadSyscallObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	

	objs.syscallMaps.OuterMap = outerMap

	files, err := readFileName("/sys/fs/cgroup/systemd/docker")
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

		// list all the processes in the subgroups of the cgroup
		log.Infof("containerProcess: %v, length: %d", containerProcess, len(containerProcess))
		for _, process := range containerProcess {
			// examine whether the process id exists in the processIDMaps
			if _, ok := processIDMaps[process.Pid]; ok {
				continue
			}
			processIDMaps[process.Pid] = true

			innerMapSpec := ebpf.MapSpec{
				//Name: "inner_map_" + strconv.Itoa(process.Pid),
				Name:       "inner_map",
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 5000,
			}
			innerMap, err := ebpf.NewMap(&innerMapSpec)
			if err != nil {
				log.Fatalf("inner_map: %v", err)
			}
			log.Println("process.Pid: ", process.Pid)
			// if process id not exists in the outer map, then create. Otherwise, skip

			if err := outerMap.Put(uint32(process.Pid), innerMap); err != nil {
				log.Fatalf("outerMap.Update: %v", err)
			}
		}

		// Attach the tracepoint
		tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    "sys_enter", // corresponds to the raw tracepoint name in SEC
			Program: objs.syscallPrograms.RawTracepointSysEnter,
		})

		if err != nil {
			log.Fatalf("attaching tracepoint: %v", err)
		}
		defer tp.Close()

	}
}
