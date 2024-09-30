package main

import (
	"docker_cgroup/cgroup"
	"docker_cgroup/perf"
	"docker_cgroup/util"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containerd/cgroups"
	cgroup2 "github.com/containerd/cgroups/v3/cgroup2"

	log "github.com/sirupsen/logrus"

	// "strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	objFileName = "./syscall_process.o"
)

func getSystemMaxProcessNumber() (int, error) {
	cmd := exec.Command("bash", "-c", "ulimit -a")
	// Run the command and capture the output
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Error running command: %v", err)
	}
	// Convert the output to a string
	outputStr := string(output)
	// only read the value of "max user processes"
	outputStr = outputStr[strings.Index(outputStr, "max user processes"):]
	maxProcessNum, _ := strconv.Atoi(strings.Fields(outputStr)[4])
	return maxProcessNum, nil

}
func createInnerMapSpec(pid uint64) ebpf.MapSpec {
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

func createOuterMap() error {
	/// Create the outer map spec for Hash of Maps
	outerMapSpec := ebpf.MapSpec{
		Name:       "outer_map",
		Type:       ebpf.HashOfMaps, // Type matches BPF_MAP_TYPE_HASH_OF_MAPS
		KeySize:    4,               // Size of keys in the outer map (uint32_t)
		ValueSize:  4,               // Size of each value (fd of inner map)
		MaxEntries: 1024,            // Maximum number of entries (keys) in the outer map
	}
	// Create the inner map spec for Array type
	innerMapSpec := createInnerMapSpec(uint64(0))

	outerMapSpec.InnerMap = &innerMapSpec

	// All inner maps are created and inserted into the outer map spec,
	outer_map, err := ebpf.NewMap(&outerMapSpec)
	if err != nil {
		return err
	}
	util.OuterMap = outer_map

	// Pin the outer map
	if err := util.OuterMap.Pin("/sys/fs/bpf/outer_map"); err != nil {
		return err
	}
	return nil
}
func perfEventArrayMap() error {
	mapSpec := &ebpf.MapSpec{
		Type:      ebpf.PerfEventArray,
		KeySize:   4,
		ValueSize: 4,
	}

	// Create the map
	cgroupEventsMap, err := ebpf.NewMap(mapSpec)
	if err != nil {
		log.Fatalf("failed to create perf event array map: %v", err)
	}
	util.PerfMap = cgroupEventsMap
	if err := util.PerfMap.Pin("/sys/fs/bpf/cgroup_events"); err != nil {
		return err
	}
	return nil
}

func createTracePointMap() error {
	if util.EbpfCollection == nil {
		spec, err := ebpf.LoadCollectionSpec(objFileName)
		if err != nil {
			panic(err)
		}
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			log.Errorf("collection error: %v", err)
		}
		util.EbpfCollection = coll
	}
	// create sysenter open tracepoint
	prog := util.EbpfCollection.Programs["tracepoint__syscalls__sys_enter_open"]
	if prog == nil {
		log.Fatalf("program not found: %v", "tracepoint__syscalls__sys_enter")
	}
	tp, err := link.Tracepoint("syscalls", "sys_enter_open", prog, nil)

	if err != nil {
		log.Fatalf("raw tracepoint error: %v", err)
	}
	util.TracepointMaps["sys_enter"] = tp

	// create cgroup_mkdir tracepoint
	prog = util.EbpfCollection.Programs["on_cgroup_create"]
	if prog == nil {
		log.Fatalf("program not found: %v", "tracepoint__cgroup__cgroup_mkdir")
	}
	tp, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "cgroup_mkdir",
		Program: prog,
	})
	if err != nil {
		log.Fatalf("raw tracepoint error: %v", err)
	}
	util.TracepointMaps["cgroup_mkdir"] = tp

	// unlinkAt:
	prog = util.EbpfCollection.Programs["unlinkAt"]
	if prog == nil {
		log.Fatalf("program not found: %v", "tracepoint__syscalls__sys_enter")
	}
	kprobe, err := link.Kprobe("do_unlinkat", prog, nil)
	if err != nil {
		log.Fatalf("sys open error: %v", err)
	}
	util.TracepointMaps["do_unlinkat"] = kprobe
	return nil
}

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	// set the maxium number of processes can run in one single container
	util.MaxMumProcessSizeInContainer, _ = getSystemMaxProcessNumber()
	if err := createOuterMap(); err != nil {
		if _, ok := err.(*os.PathError); !ok {
			log.Info("outer map already exists")
		} else {
			log.Fatalf("creating outer map: %v", err)
		}
	}
	if err := perfEventArrayMap(); err != nil {
		if _, ok := err.(*os.PathError); !ok {
			log.Info("perf event array map already exists")
		} else {
			log.Fatalf("creating perf event array map: %v", err)
		}
	}

}

func main() {
	if err := createTracePointMap(); err != nil {
		log.Fatalf("create tracepoint map: %v", err)
	}
	// for each value in tracepointMaps, defer the close
	for _, tp := range util.TracepointMaps {
		defer tp.Close()
	}

	dirPath := "/sys/fs/cgroup/system.slice"

	files, err := filepath.Glob(filepath.Join(dirPath, "docker-*.scope"))
	if err != nil {
		fmt.Printf("Error reading directory: %v\n", err)
		return
	}

	// Remove the "/sys/fs/cgroup" prefix from each file path
	var updatedFiles []string
	prefixToRemove := "/sys/fs/cgroup"
	for _, file := range files {
		updatedFile := strings.TrimPrefix(file, prefixToRemove)
		updatedFiles = append(updatedFiles, updatedFile)
	}

	var cgroupV2 bool

	if cgroups.Mode() == cgroups.Unified {
		cgroupV2 = true
	}
	log.Infof("cgroupV2: %v", cgroupV2)

	for _, cgroupPath := range updatedFiles {
		// load the group which belongs to system.slice
		cg, err := cgroup2.Load(cgroupPath)
		if err != nil {
			log.Fatal(err)
		}

		processIDList, err := cg.Procs(true)

		if err != nil {
			log.Fatal(err)
		}

		for _, processID := range processIDList {
			// get  inode number of the cgroup id
			cgroupInodeNum, err := cgroup.GetCurrentCgroupID(uint64(processID))
			if err != nil {
				log.Fatal(err)
			}

			util.ProcessIDMaps[cgroupInodeNum] = append(util.ProcessIDMaps[uint64(cgroupInodeNum)], processID)
		}
	}

	for cgroupInodeNum, _ := range util.ProcessIDMaps {
		// examine whether the process id exists in the processIDMaps
		innerMapSpec := createInnerMapSpec(cgroupInodeNum)
		innerMap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			log.Fatalf("inner_map: %v", err)
		}
		log.Println("cgroupInodeNum: ", cgroupInodeNum)
		// Populate the inner map with some key-value pairs
		// Example: Insert key 0 with value 12345, adjust logic based on your data
		key := uint32(0)       // Example key
		value := uint32(12345) // Example value, replace with your actual value logic

		err = innerMap.Update(&key, &value, ebpf.UpdateAny)
		if err != nil {
			log.Fatalf("Failed to update inner map for cgroupInodeNum %d: %v", cgroupInodeNum, err)
		}

		// if err := util.OuterMap.Put(uint32(cgroupInodeNum), innerMap); err != nil {
		if err := util.OuterMap.Update(uint32(cgroupInodeNum), uint32(innerMap.FD()), ebpf.UpdateAny); err != nil {
			log.Fatalf("outerMap.Update: %v", err)
		}

	}

	perf.ReadMessageFromPerfBuffer("cgroup_events")

}
