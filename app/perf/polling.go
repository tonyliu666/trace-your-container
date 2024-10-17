package perf

import (
	"bytes"
	"docker_cgroup/cgroup"
	"docker_cgroup/util"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/cilium/ebpf/perf"
)

type Event struct {
	CgroupID uint32
}

func MessagePerfBufferCreateInnerMap(perfName string) {
	var event Event
	reader, err := perf.NewReader(util.EbpfCollection.Maps[perfName], os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer reader.Close()

	for {
		record, err := reader.Read()
		if err != nil {
			panic(err)
		}
		err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			fmt.Printf("Error parsing event: %v\n", err)
			continue
		}
		fmt.Printf("Event - CgroupID: %d\n", event.CgroupID)
		err = cgroup.InsertEntryToInnerMap(event.CgroupID)
		if err != nil {
			fmt.Printf("Error inserting entry to inner map: %v\n", err)
		}
		fmt.Printf("Inserted inner map %d to the entry of outer map\n", event.CgroupID)
	}
}
