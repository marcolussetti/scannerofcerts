package furiousscanlib

import (
	"context"
	"fmt"
	furiousscan "github.com/liamg/furious/scan"
	"inet.af/netaddr"
	"os"
	"sort"
	"time"
)

// PortScanHost Struct type for port scan results, to avoid having to re-import furious elsewhere
type PortScanHost struct {
	Host netaddr.IP  // To avoid having to implement sorting, among other things
	Name string
	OpenPorts []int
	ClosedPorts []int
	FilteredPorts []int
}

// PortScan Wrapper for the furious library
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
		netaddrIP, _ := netaddr.FromStdIP(result.Host)
		hosts = append(hosts, PortScanHost{Host: netaddrIP, Name: result.Name, OpenPorts: result.Open, ClosedPorts: result.Closed, FilteredPorts: result.Filtered})
	}

	return hosts
}

// GetAliveHosts Filters out hosts without open ports
func GetAliveHosts(hosts []PortScanHost) []PortScanHost {
	var filteredHosts []PortScanHost
	for _, host := range hosts {
		if len(host.OpenPorts) > 0 {
			filteredHosts = append(filteredHosts, host)
		}
	}

	return filteredHosts
}
// ByIP implements sort.Interface based on the Host field
type ByIP []PortScanHost

func (a ByIP) Len() int           { return len(a) }
func (a ByIP) Less(i, j int) bool {	return a[i].Host.Less(a[j].Host) }
func (a ByIP) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// SortByIP Sorts PortScanHost by IP
func SortByIP (hosts ByIP) []PortScanHost {
	sort.Sort(hosts)
	return hosts
}
