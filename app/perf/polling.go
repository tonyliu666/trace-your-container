package perf

import (
	"bytes"
	"docker_cgroup/util"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/cilium/ebpf/perf"
)

type Event struct {
	CgroupID uint32
}

func ReadMessageFromPerfBuffer(perfName string) {
	var event Event
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
		err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			fmt.Printf("Error parsing event: %v\n", err)
			continue
		}
		fmt.Printf("Event - CgroupID: %d\n", event.CgroupID)

	}
}
