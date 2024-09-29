package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	// "strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	objFileName = "./syscall_process.o"
)

var outerMap *ebpf.Map
var perfMap *ebpf.Map

// read the output "max user processes" from ulimit -a
var maxMumProcessSizeInContainer int

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
		Type:       ebpf.Hash,                            // Type changed to Array to match BPF_MAP_TYPE_ARRAY
		KeySize:    4,                                    // Size of keys in the inner map (uint32_t)
		ValueSize:  4,                                    // Size of values in the inner map (uint32_t)
		MaxEntries: uint32(maxMumProcessSizeInContainer), // Maximum number of entries in the inner map
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
	outerMap = outer_map

	// Pin the outer map
	if err := outerMap.Pin("/sys/fs/bpf/outer_map"); err != nil {
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
	perfMap = cgroupEventsMap
	if err := perfMap.Pin("/sys/fs/bpf/cgroup_events"); err != nil {
		return err
	}
	return nil
}

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	// set the maxium number of processes can run in one single container
	maxMumProcessSizeInContainer, _ = getSystemMaxProcessNumber()
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

// create process id maps, value  is the list of uint64
var processIDMaps = make(map[uint64][]uint64)

func main() {
	// pin the syscall_bpfeb.o to /sys/fs/bpf/syscall_bpfeb
	spec, err := ebpf.LoadCollectionSpec(objFileName)
	if err != nil {
		panic(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Error("collection error: %v", err)
	}
	prog := coll.Programs["tracepoint__syscalls__sys_enter"]
	if prog == nil {
		log.Fatalf("program not found: %v", "tracepoint__syscalls__sys_enter")
	}
	tp, err := link.Tracepoint("syscalls", "sys_enter", prog, nil)
	if err != nil {
		log.Fatalf("tracepoint error: %v", err)
	}

	defer tp.Close()

	// dirPath := "/sys/fs/cgroup/system.slice"

	// files, err := filepath.Glob(filepath.Join(dirPath, "docker-*.scope"))
	// if err != nil {
	// 	fmt.Printf("Error reading directory: %v\n", err)
	// 	return
	// }

	// // Remove the "/sys/fs/cgroup" prefix from each file path
	// var updatedFiles []string
	// prefixToRemove := "/sys/fs/cgroup"
	// for _, file := range files {
	// 	updatedFile := strings.TrimPrefix(file, prefixToRemove)
	// 	updatedFiles = append(updatedFiles, updatedFile)
	// }

	// var cgroupV2 bool

	// if cgroups.Mode() == cgroups.Unified {
	// 	cgroupV2 = true
	// }
	// log.Infof("cgroupV2: %v", cgroupV2)

	// for _, cgroupPath := range updatedFiles {
	// 	// load the group which belongs to system.slice
	// 	cg, err := cgroup2.Load(cgroupPath)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}

	// 	processIDList, err := cg.Procs(true)

	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}

	// 	for _, processID := range processIDList {
	// 		// get  inode number of the cgroup id
	// 		cgroupInodeNum, err := cgroup.GetCurrentCgroupID(uint64(processID))
	// 		if err != nil {
	// 			log.Fatal(err)
	// 		}

	// 		processIDMaps[cgroupInodeNum] = append(processIDMaps[uint64(cgroupInodeNum)], processID)
	// 	}
	// }
	// log.Infof("processIDMaps: %v, length: %d", processIDMaps, len(processIDMaps))

	// for cgroupInodeNum, _ := range processIDMaps {
	// 	// examine whether the process id exists in the processIDMaps
	// 	innerMapSpec := createInnerMapSpec(cgroupInodeNum)
	// 	innerMap, err := ebpf.NewMap(&innerMapSpec)
	// 	if err != nil {
	// 		log.Fatalf("inner_map: %v", err)
	// 	}

	// 	if err := outerMap.Put(uint32(cgroupInodeNum), innerMap); err != nil {
	// 		log.Fatalf("outerMap.Update: %v", err)
	// 	}

	// }

	// // Attach the tracepoint
	// tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
	// 	Name:    "sys_enter", // corresponds to the raw tracepoint name in SEC
	// 	Program: objs.syscallPrograms.RawTracepointSysEnter,
	// })

	// if err != nil {
	// 	log.Fatalf("attaching tracepoint: %v", err)
	// }
	// defer tp.Close()

	// perf.ReadMessageFromPerfBuffer("cgroup_events")

}
