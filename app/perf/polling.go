package perf

import (
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

func ReadMessageFromPerfBuffer(perfName string) {
	spec, err := ebpf.LoadCollectionSpec("syscall_bpfel.o")
	if err != nil {
		log.Fatalf("loading collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating collection: %v", err)
	}
	events, err := perf.NewReader(coll.Maps["cgroup_events"], os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer events.Close()
	for {
		record, err := events.Read()
		if err != nil {
			panic(err)
		}
		fmt.Println("Event: ", record)

	}
}
