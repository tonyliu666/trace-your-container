package bpfperf

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func ReadMessageFromRingBuffer(perfName string) {
	bpfRingBuffer, err := ebpf.LoadPinnedMap("/sys/fs/bpf/"+perfName, nil)
	if err != nil {
		log.Fatalf("loading pinned map: %v", err)
	}
	defer bpfRingBuffer.Close()

	// Set up a ring buffer reader for the map
	rd, err := ringbuf.NewReader(bpfRingBuffer)
	if err != nil {
		log.Fatalf("creating ringbuf reader: %v", err)
	}
	defer rd.Close()

	fmt.Println("Listening for events...")

	// Polling loop to read data from the ring buffer
	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			log.Printf("reading from ring buffer: %v", err)
			continue
		}

		// Extract the event data from the record
		value := binary.LittleEndian.Uint32(record.RawSample)

		// Process the uint32 value (just print it in this case)
		fmt.Printf("Received uint32 value: %d\n", value)

	}

}
