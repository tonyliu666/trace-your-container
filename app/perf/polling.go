package perf

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

func ReadMessageFromPerfBuffer(perfName string) {
	bpfMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/"+perfName, nil)
	if err != nil {
		log.Fatalf("loading pinned map: %v", err)
	}

	reader, err := perf.NewReader(bpfMap, 4096)
	if err != nil {
		log.Fatalf("creating perf buffer reader: %v", err)
	}
	defer reader.Close()
	// read the data from the perf buffer

	for {
		log.Printf("Reading from perf buffer\n")
		sample, err := reader.Read()
		log.Printf("Received sample: %+v\n", sample.RawSample)
		if err != nil {
			log.Fatalf("reading from perf buffer: %v", err)
		}

	}
}