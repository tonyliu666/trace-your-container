package perf

import (
	"docker_cgroup/util"
	"fmt"
	"os"

	"github.com/cilium/ebpf/perf"
)

func ReadMessageFromPerfBuffer(perfName string) {
	events, err := perf.NewReader(util.EbpfCollection.Maps[perfName], os.Getpagesize())
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
