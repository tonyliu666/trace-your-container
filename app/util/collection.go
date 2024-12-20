package util

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var (
	// create process id maps, value  is the list of uint64
	ProcessIDMaps = make(map[uint64][]uint64)
	// create tracepoint maps, key is the name of the tracepoint, value is the link.Link
	TracepointMaps = make(map[string]link.Link)
	// read the output "max user processes" from ulimit -a
	MaxMumProcessSizeInContainer int
	EbpfCollection               *ebpf.Collection
)
