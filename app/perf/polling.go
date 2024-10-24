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

const MAX_PATH_LEN = 64

type innerMapEvent struct {
	CgroupID uint32
}

type fileDeleteEvent struct {
	Filepath [MAX_PATH_LEN]byte // Fixed-size array for the path
	Offsets  int32              // Match C 'int' to Go 'int32'
}

func MessagePerfBufferCreateInnerMap(perfName string) {
	var event innerMapEvent
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

func DeleteFileEvent(perfName string) {
	var event fileDeleteEvent
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
		// print the path  combining the path and the offset
		fmt.Printf("file name: %s\n", event.Filepath[event.Offsets:])

	}
}
