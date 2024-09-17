package main

import (
	"log"
	"os/exec"
	"strings"
)

func main() {
	// execute ulimit -u
	// Define the command you want to execute
	cmd := exec.Command("bash", "-c", "ulimit -a")

	// Run the command and capture the output
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Error running command: %v", err)
	}
	// Convert the output to a string
	outputStr := string(output)
	// only read the value of "max user processes"
	outputStr = outputStr[strings.Index(outputStr, "max user processes"):]
	log.Printf("Output: %s", outputStr)
	/*
		the output will be:
		2024/09/17 23:14:29 Output: max user processes                  (-u) 47069
		virtual memory              (kbytes, -v) unlimited
		file locks                          (-x) unlimited
		I want to extract the number 47069
	*/
	// Extract the number
	num := strings.Fields(outputStr)[4]
	log.Printf("Number: %s", num)

}
