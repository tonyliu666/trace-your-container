package main

import (
	"math/rand"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"

	cgroups "github.com/containerd/cgroups"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go syscall syscall_process.c -- -I../headers

const BPF_F_INNER_MAP = 0x1000

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	outerMapSpec := ebpf.MapSpec{
		Name:       "outer_map",
		Type:       ebpf.ArrayOfMaps,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 5, // We'll have 5 maps inside this map
		Contents:   make([]ebpf.MapKV, 5),
		InnerMap: &ebpf.MapSpec{
			Name:      "inner_map",
			Type:      ebpf.Array,
			KeySize:   4,
			ValueSize: 4,
			Flags:     BPF_F_INNER_MAP,
			// We set this to 1 now, but this inner map spec gets copied
			// and altered later.
			MaxEntries: 100,
		},
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// For each entry we want to create in the outer map...
	for i := uint32(0); i < outerMapSpec.MaxEntries; i++ {
		// Copy the inner map spec
		innerMapSpec := outerMapSpec.InnerMap.Copy()

		// Randomly generate inner map length
		innerMapSpec.MaxEntries = uint32(r.Intn(50) + 1) // Can't be zero.

		// populate the inner map contents
		innerMapSpec.Contents = make([]ebpf.MapKV, innerMapSpec.MaxEntries)

		for j := range innerMapSpec.Contents {
			innerMapSpec.Contents[uint32(j)] = ebpf.MapKV{Key: uint32(j), Value: uint32(0xCAFE)}
		}

		// Create the inner map
		innerMap, err := ebpf.NewMap(innerMapSpec)
		if err != nil {
			log.Fatalf("inner_map: %v", err)
		}

		defer innerMap.Close()

		// Inner map is created successfully and lives in the kernel,
		// let's add it to the contents of the outer map spec.
		outerMapSpec.Contents[i] = ebpf.MapKV{Key: i, Value: innerMap}
	}

	// All inner maps are created and inserted into the outer map spec,
	// time to create the outer map.
	outerMap, err := ebpf.NewMap(&outerMapSpec)
	if err != nil {
		log.Fatalf("outer_map: %v", err)
	}
	defer outerMap.Close()

	// Pin the outer map
	if err := outerMap.Pin("/sys/fs/bpf/outer_map"); err != nil {
		// ignore the error if the map is already pinned
		if _, ok := err.(*os.PathError); !ok {
			log.Fatalf("pinning outer_map: %v", err)
		}
	}

	objs := syscallObjects{}
	if err := loadSyscallObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Link the process_sys_call program to the cgroup.
	l, err := link.AttachCgroup(link.CgroupOptions{
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CollectSysCalls,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// get the processes in the container

	// Show all the filenames of files under /var/run/docker/containerd
	dirname := "/var/run/docker/containerd"

	dir, err := os.Open(dirname)
	if err != nil {
		log.Fatal(err)
	}
	defer dir.Close()

	// Read all the files in the directory
	files, err := dir.Readdirnames(0) // 0 to read all files and directories
	if err != nil {
		log.Fatal(err)
	}

	var cgroupV2 bool
	cgroupList := []cgroups.Cgroup{}
	// if cgroups.Mode() == cgroups.Hybrid {
	// 	cgroupV2 = true
	// }
	if cgroups.Mode() == cgroups.Unified {
		cgroupV2 = true
	}
	log.Infof("cgroupV2: %v", cgroupV2)

	if !cgroupV2 {
		containerProcess := []cgroups.Process{}
		for _, cgroupPath := range files {
			// cg, err := cgroups.Load(cgroups.Systemd, cgroups.StaticPath("/docker/"))
			cg, err := cgroups.Load(cgroups.Systemd, cgroups.StaticPath("/docker/"+cgroupPath))
			if err != nil {
				log.Fatal(err)
			}

			cgroupList = append(cgroupList, cg)
		}
		// print the cgroup status in cgroupList
		for _, cg := range cgroupList {
			for _, subsys := range cg.Subsystems() {
				log.Infof("cgroup state: %s, subsystem: %s", cg.State(), subsys.Name())
				processes, _ := cg.Tasks(subsys.Name(), true)
				for _, pid := range processes {
					containerProcess = append(containerProcess, pid)
				}
			}
		}
		for _, process := range containerProcess {
			log.Info("pid: ", process.Pid)
		}

	}

}
