package perf

import (
	"bytes"
	"docker_cgroup/cgroup"
	"docker_cgroup/util"
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/perf"
)

const MAX_PATH_LEN = 64

type innerMapEvent struct {
	CgroupID       uint32
	InsertORdelete int32
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

		if event.InsertORdelete == 1 {
			err = cgroup.InsertEntryToInnerMap(event.CgroupID)
			if err != nil {
				fmt.Printf("Error inserting entry to inner map: %v\n", err)
			}
			log.Printf("Inserted inner map %d to the entry of outer map\n", event.CgroupID)
			err = cgroup.InsertEntryToIngressHashMap(event.CgroupID)
			if err != nil {
				log.Fatalf("Error inserting entry to ingress hashmap: %v\n", err)
			}
			log.Printf("Inserted ingress hashmap %d entry\n", event.CgroupID)
			err = cgroup.InsertEntryToEgressHashMap(event.CgroupID)
			if err != nil {
				log.Fatalf("Error inserting entry to egress hashmap: %v\n", err)
			}
			log.Printf("Inserted egress hashmap %d entry\n", event.CgroupID)
		} else {
			err = cgroup.DeleteEntryFromInnerMap(event.CgroupID)
			if err != nil {
				fmt.Printf("Error deleting entry from inner map: %v\n", err)
			}
			log.Printf("Deleted inner map %d from the entry of outer map\n", event.CgroupID)
			err = cgroup.DeleteEntryFromIngressHashMap(event.CgroupID)
			if err != nil {
				log.Fatalf("Error deleting entry from ingress hashmap: %v\n", err)
			}
			log.Printf("Deleted ingress hashmap %d entry\n", event.CgroupID)
			err = cgroup.DeleteEntryFromEgressHashMap(event.CgroupID)
			if err != nil {
				log.Fatalf("Error deleting entry from egress hashmap: %v\n", err)
			}
			log.Printf("Deleted egress hashmap %d entry\n", event.CgroupID)

		}
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
