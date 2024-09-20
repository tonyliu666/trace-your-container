package perf

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

func ReadMessageFromPerfBuffer(perfName string) {
	bpfMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/"+perfName, nil)
	if err != nil {
		log.Fatalf("loading pinned map: %v", err)
	}

	// Create a perf buffer reader with a 32KB buffer per CPU
	reader, err := perf.NewReader(bpfMap, 32*1024)
	if err != nil {
		log.Fatalf("creating perf buffer reader: %v", err)
	}
	defer reader.Close()

	// Channel to handle SIGINT (Ctrl+C) to gracefully exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Listening for events...")

	// Poll for events in a separate goroutine
	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				if err == perf.ErrClosed {
					break
				}
				log.Printf("reading from perf buffer: %v", err)
				continue
			}

			// Handle event (this corresponds to your C function `handle_event`)
			handleEvent(record)
		}
	}()

	<-sigs // Wait for a signal (Ctrl+C)

	fmt.Println("Shutting down...")
}
