package scancertlib

import (
	"context"
	"fmt"
	furiousscan "github.com/liamg/furious/scan"
	"net"
	"os"
	"time"
)

// PortScanHost Struct type for port scan results, to avoid having to re-import furious elsewhere
type PortScanHost struct {
	Host net.IP
	Name string
	OpenPorts []int
	ClosedPorts []int
	FilteredPorts []int
}

func PortScan(scanRange string, scanPorts []int, timeout time.Duration, parallelism int) []PortScanHost {
	targetIterator := furiousscan.NewTargetIterator(scanRange)
	scanner := furiousscan.NewSynScanner(targetIterator, time.Millisecond*time.Duration(2000), 1000)
	if err := scanner.Start(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	ctx, _ := context.WithCancel(context.Background())
	results, err := scanner.Scan(ctx, furiousscan.DefaultPorts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var hosts []PortScanHost
	for _, result := range results {
		hosts = append(hosts, PortScanHost{Host: result.Host, Name: result.Name, OpenPorts: result.Open, ClosedPorts: result.Closed, FilteredPorts: result.Filtered})
	}

	return hosts
}

func GetAliveHosts(hosts []PortScanHost) []PortScanHost {
	var filteredHosts []PortScanHost
	for _, host := range hosts {
		if len(host.OpenPorts) > 0 {
			filteredHosts = append(filteredHosts, host)
		}
	}

	return filteredHosts
}