package main

// scannerofcerts is a portable Go application that scans for, and reports on,
// certificates in a specified subnet.
//
// It scan each host in the subnet on a customizable range of ports, aiming to
// discover hosts you may have well forgotten the configuration of.
// It will then group the hosts by certificate, and report on the certificate's
// validity, expiration date, and applicable hosts/ports combinations.

import (
	"fmt"
	"scannerofcerts/internal/furiousscanlib"
	"time"
)

var (
	scanTimeout = time.Millisecond*time.Duration(2000)
	scanParallelism = 1000
)

func main() {
	// Check if not running as root, required for posts
	//if os.Getuid() > 0 {
	//	fmt.Println("This program must be run as root/privileged user.")
	//	os.Exit(1)
	//}

	// Firstly, we shall scan the hosts given to determine which ports to further investigate
	scanResults := furiousscanlib.PortScan("10.0.0.0/24", []int{80, 443}, scanTimeout, scanParallelism)
	scanResults = furiousscanlib.GetAliveHosts(scanResults)
	scanResults = furiousscanlib.SortByIP(scanResults)

	for _, result := range scanResults {
		fmt.Print(fmt.Sprintf("%s (%s). Open ports: ", result.IP, result.Name))
		for i, port := range result.OpenPorts {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(fmt.Sprintf("%d", port))
		}
		fmt.Println()
	}

}
