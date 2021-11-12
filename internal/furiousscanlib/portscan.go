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

type Port int

// PortScanHost Struct type for port scan results, to avoid having to re-import furious elsewhere
type PortScanHost struct {
	IP            netaddr.IP // To avoid having to implement sorting, among other things
	Name          string
	OpenPorts     Ports
	ClosedPorts   Ports
	FilteredPorts Ports
}

// PortScan Wrapper for the furious library
func PortScan(scanRange string, scanPorts []int, timeout time.Duration, parallelism int) []PortScanHost {
	targetIterator := furiousscan.NewTargetIterator(scanRange)
	scanner := furiousscan.NewSynScanner(targetIterator, timeout, parallelism)
	if err := scanner.Start(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	ctx, _ := context.WithCancel(context.Background())
	results, err := scanner.Scan(ctx, scanPorts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var hosts []PortScanHost
	for _, result := range results {
		netaddrIP, _ := netaddr.FromStdIP(result.Host)
		var openPorts Ports = result.Open
		sort.Sort(openPorts)
		var closedPorts Ports = result.Closed
		sort.Sort(closedPorts)
		var filteredPorts Ports = result.Filtered
		sort.Sort(filteredPorts)
		hosts = append(hosts, PortScanHost{IP: netaddrIP, Name: result.Name, OpenPorts: openPorts, ClosedPorts: closedPorts, FilteredPorts: filteredPorts})
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

// ByIP implements sort.Interface based on the IP field
type ByIP []PortScanHost

func (a ByIP) Len() int           { return len(a) }
func (a ByIP) Less(i, j int) bool { return a[i].IP.Less(a[j].IP) }
func (a ByIP) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// SortByIP Sorts PortScanHost by IP
func SortByIP(hosts ByIP) []PortScanHost {
	sort.Sort(hosts)
	return hosts
}

type Ports []int

func (a Ports) Len() int           { return len(a) }
func (a Ports) Less(i, j int) bool { return a[i] < a[j] }
func (a Ports) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
