package main

// goscancerts is a portable Go application that scans for, and reports on,
// certificates in a specified subnet.
//
// It scan each host in the subnet on a customizable range of ports, aiming to
// discover hosts you may have well forgotten the configuration of.
// It will then group the hosts by certificate, and report on the certificate's
// validity, expiration date, and applicable hosts/ports combinations.

import (
	"context"
	"fmt"
	"github.com/liamg/furious/scan"
	"os"
	"time"
)

func main() {
	// Check if not running as root
	if os.Getuid() > 0 {
		fmt.Println("This program must be run as root/privileged user.")
		os.Exit(1)
	}

	targetIterator := scan.NewTargetIterator("10.0.0.0/24")
	scanner := scan.NewSynScanner(targetIterator, time.Millisecond*time.Duration(2000), 1000)
	if err := scanner.Start(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	ctx, _ := context.WithCancel(context.Background())
	results, err := scanner.Scan(ctx, scan.DefaultPorts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	hostsAlive := []scan.Result{}

	for _, result := range results {
		if len(result.Open) > 0 {
			hostsAlive = append(hostsAlive, result)
		}
	}

	for _, result := range hostsAlive {
		scanner.OutputResult(result)
	}

}
