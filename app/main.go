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

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
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
