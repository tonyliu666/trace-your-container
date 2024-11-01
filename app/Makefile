CC := clang
CFLAGS := -O2 -g -target bpf -I/usr/include -I/usr/src/linux-headers-$(shell uname -r)/include -D__BPF_TRACING__
SRC := ./syscall_process.c
OBJ := ./syscall_process.o
VMLINUX_H := ./vmlinux.h

all: build_ebpf build_go

build_ebpf: $(VMLINUX_H) $(OBJ)
docker: build_ebpf docker_build_go

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

$(OBJ): $(SRC) $(VMLINUX_H)
	$(CC) $(CFLAGS) -c $< -o $@ || (echo "Error building eBPF program"; exit 1)  # Stop on error

docker_build_go:
	# go build main.go || (echo "Error running Go program"; exit 1)  # Stop on error
	go build -o main main.go || (echo "Error running Go program"; exit 1)  # Stop on error

build_go:
	go build -o main main.go || (echo "Error running Go program"; exit 1)  # Stop on error
	sudo ./main
clean:
	rm -f $(OBJ) 

.PHONY: all build_ebpf build_go clean