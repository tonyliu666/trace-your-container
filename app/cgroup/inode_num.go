package cgroup

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// getCurrentCgroupID retrieves the cgroup ID (inode) for the current process
func GetCurrentCgroupID(pid uint64) (uint64, error) {
	// Open the /proc/self/cgroup file
	file, err := os.Open("/proc/" + strconv.Itoa(int(pid)) + "/cgroup")
	if err != nil {
		return 0, fmt.Errorf("failed to open /proc/self/cgroup: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var cgroupPath string
	for scanner.Scan() {
		line := scanner.Text()
		// The format of /proc/self/cgroup is something like: 0::/sys/fs/cgroup/unified
		parts := strings.Split(line, ":")
		if len(parts) == 3 {
			cgroupPath = parts[2] // Extract the cgroup path
			break
		}
	}

	if cgroupPath == "" {
		return 0, fmt.Errorf("cgroup path not found in /proc/self/cgroup")
	}

	// Construct the full path to the cgroup directory
	cgroupFullPath := filepath.Join("/sys/fs/cgroup", cgroupPath)

	// Get the inode of the cgroup directory (which serves as the cgroup ID)
	var stat syscall.Stat_t
	if err := syscall.Stat(cgroupFullPath, &stat); err != nil {
		return 0, fmt.Errorf("failed to stat cgroup path: %v", err)
	}

	return stat.Ino, nil
}
