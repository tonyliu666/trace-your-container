// pin the ../app/syscall_bpfeb to /sys/fs/bpf/syscall_bpfeb
package main

import (
	"log"
	elf "github.com/safchain/ebpf/elf"
)

func main() {
	customELFFileName := "syscall_bpfeb.o"
	b := elf.NewModule(customELFFileName)
	if err := b.Load(objs); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

}
