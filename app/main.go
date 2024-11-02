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
	"sync"

	"github.com/containerd/cgroups"
	cgroup2 "github.com/containerd/cgroups/v3/cgroup2"

	log "github.com/sirupsen/logrus"

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
	innerMapSpec := cgroup.CreateInnerMapSpec(uint64(0))

	outerMapSpec.InnerMap = &innerMapSpec

	// All inner maps are created and inserted into the outer map spec,
	outer_map, err := ebpf.NewMap(&outerMapSpec)
	if err != nil {
		return err
	}

	// Pin the outer map
	if err := outer_map.Pin("/sys/fs/bpf/outer_map"); err != nil {
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

	if err := cgroupEventsMap.Pin("/sys/fs/bpf/cgroup_events"); err != nil {
		return err
	}
	mapSpec = &ebpf.MapSpec{
		Type:      ebpf.PerfEventArray,
		KeySize:   4,
		ValueSize: 4, // 64 bytes for the event path and 4 bytes for the offsets(defined in syscall_process.c)
	}
	containerEventsMap, err := ebpf.NewMap(mapSpec)
	if err != nil {
		log.Fatalf("failed to create perf event array map: %v", err)
	}

	if err := containerEventsMap.Pin("/sys/fs/bpf/container_events"); err != nil {
		return err
	}

	return nil
}

func createIngressCgroupMap() error {
	// Create the map

	// create ingress map for cgroup
	ingressMapSpec := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1024,
	}
	// Create the map
	cgroupMap, err := ebpf.NewMap(ingressMapSpec)
	if err != nil {
		log.Fatalf("failed to create cgroup map: %v", err)
	}
	// util.CgroupIngressMap = cgroupMap
	// if err := util.CgroupIngressMap.Pin("/sys/fs/bpf/cgroup_ingress_map"); err != nil {
	// 	return err
	// }
	if err := cgroupMap.Pin("/sys/fs/bpf/cgroup_ingress_map"); err != nil {
		return err
	}

	return nil

}
func createEgressCgroupMap() error {
	egressMapSpec := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1024,
	}
	cgroupNewMap, err := ebpf.NewMap(egressMapSpec)
	if err != nil {
		log.Fatalf("failed to create cgroup map: %v", err)
	}
	// util.CgroupEgressMap = cgroupNewMap
	// if util.CgroupEgressMap == nil {
	// 	log.Fatalf("CgroupEgressMap is nil here")
	// }
	// if err := util.CgroupEgressMap.Pin("/sys/fs/bpf/cgroup_egress_map"); err != nil {
	// 	return err
	// }
	if err := cgroupNewMap.Pin("/sys/fs/bpf/cgroup_egress_map"); err != nil {
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
		log.Fatalf("raw tracepoint error: 0 %v", err)
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
		log.Fatalf("raw tracepoint error 1: %v", err)
	}
	util.TracepointMaps["cgroup_mkdir"] = tp

	// create cgroup_rmdir tracepoint
	prog = util.EbpfCollection.Programs["on_cgroup_delete"]
	if prog == nil {
		log.Fatalf("program not found: %v", " on_cgroup_delete")
	}
	tp, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "cgroup_rmdir",
		Program: prog,
	})
	if err != nil {
		log.Fatalf("raw tracepoint error 2: %v", err)
	}
	util.TracepointMaps["cgroup_rmdir"] = tp

	// create sysEnterUnlink tracepoint
	prog = util.EbpfCollection.Programs["sysEnterUnlink"]
	if prog == nil {
		log.Fatalf("program not found: %v", "sysEnterUnlink")
	}
	tp, err = link.Tracepoint("syscalls", "sys_enter_unlink", prog, nil)

	if err != nil {
		log.Fatalf("raw tracepoint error 3: %v", err)
	}
	util.TracepointMaps["sys_enter_unlink"] = tp

	// tp_btf/sys_enter
	prog = util.EbpfCollection.Programs["sysEnter"]
	if prog == nil {
		log.Fatalf("program not found: %v", "sysEnter")
	}
	tp, err = link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		log.Fatalf("raw tracepoint error 4: %v", err)
	}
	util.TracepointMaps["sys_enter"] = tp

	return nil

}

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	// set the maxium number of processes can run in one single container
	util.MaxMumProcessSizeInContainer, _ = getSystemMaxProcessNumber()
	log.Infof("MaxMumProcessSizeInContainer: %v", util.MaxMumProcessSizeInContainer)
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
	if err := createIngressCgroupMap(); err != nil {
		if _, ok := err.(*os.PathError); !ok {
			log.Info("ingress hash already exists")
		} else {
			log.Fatalf("creating ingress hash: %v", err)
		}
	}
	if err := createEgressCgroupMap(); err != nil {
		if _, ok := err.(*os.PathError); !ok {
			log.Info("egress hash already exists")
		} else {
			log.Fatalf("creating egress hash: %v", err)
		}
	}

}

func main() {
	if err := createTracePointMap(); err != nil {
		log.Fatalf("create tracepoint map: %v", err)
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

	// update the BPFCgroupNetworkDirections
	for _, filepath := range updatedFiles {
		cgroup.BPFCgroupNetworkDirections = append(cgroup.BPFCgroupNetworkDirections, cgroup.BPFCgroupNetworkDirection{
			Name:       "ingress",
			AttachType: ebpf.AttachCGroupInetIngress,
			FilePath:   prefixToRemove + filepath,
		})
		cgroup.BPFCgroupNetworkDirections = append(cgroup.BPFCgroupNetworkDirections, cgroup.BPFCgroupNetworkDirection{
			Name:       "egress",
			AttachType: ebpf.AttachCGroupInetEgress,
			FilePath:   prefixToRemove + filepath,
		})
	}
	// Attach the program to monitor the network traffic
	cgroup.AttachBPFCgroupNetworkDirections()

	// for each value in tracepointMaps, defer the close
	for _, tp := range util.TracepointMaps {
		defer tp.Close()
	}
	// for each map in collection.go, defer the close
	// defer theCollectionClose()

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
		log.Println("cgroupInodeNum:", cgroupInodeNum)
		innerMapSpec := cgroup.CreateInnerMapSpec(cgroupInodeNum)
		innerMap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			log.Fatalf("inner_map: %v", err)
		}

		maps := util.EbpfCollection.Maps["outer_map"]

		// if err := util.OuterMap.Put(uint32(cgroupInodeNum), innerMap); err != nil {
		if err := maps.Update(uint32(cgroupInodeNum), uint32(innerMap.FD()), ebpf.UpdateAny); err != nil {
			log.Fatalf("outerMap.Update: %v", err)
		}
		// update the ingress hashmap
		ingressHash := util.EbpfCollection.Maps["cgroup_ingress_map"]
		if err := ingressHash.Update(uint32(cgroupInodeNum), uint32(0), ebpf.UpdateAny); err != nil {
			log.Fatalf("ingressHash.Update: %v", err)
		}
		// update the egress hashmap
		egressHash := util.EbpfCollection.Maps["cgroup_egress_map"]
		if err := egressHash.Update(uint32(cgroupInodeNum), uint32(0), ebpf.UpdateAny); err != nil {
			log.Fatalf("egressHash.Update: %v", err)
		}

	}
	// main go routine wait until the following go routines terminated
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		perf.MessagePerfBufferCreateInnerMap("cgroup_events")
		defer wg.Done()
	}()

	go func() {
		perf.DeleteFileEvent("container_events")
		defer wg.Done()
	}()

	wg.Wait()

}
