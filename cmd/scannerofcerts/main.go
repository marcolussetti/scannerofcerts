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
	log "github.com/sirupsen/logrus"
	"os"
	"scannerofcerts/internal/furiousscanlib"
	"scannerofcerts/internal/scancertlib"
	"time"
)

var (
	logLevel = log.DebugLevel
	scanTimeout = time.Millisecond*time.Duration(20000)
	scanParallelism = 1000
	scanPorts = []int{22, 23, 80, 443}
)

func main() {
	// Firstly, we shall handle flags, initial setup, and so forth
	log.SetLevel(logLevel)

	// TODO: consider if we ought to provide a fallback to a non-privileged TCP/Connect scan method
	if os.Getuid() > 0 {
		log.Error("scannerofcerts requires root privileges to be able to port scan. Thank you for your understanding.")
		os.Exit(1)
	}

	// Secondly, we shall scan the hosts given to determine which ports to further investigate
	log.Debug("Begin furious-backed port scan")
	scanResults := furiousscanlib.PortScan("10.0.0.0/24", scanPorts, scanTimeout, scanParallelism)
	log.Debug("Completed furious-backed port scan")
	scanResults = furiousscanlib.GetAliveHosts(scanResults)
	scanResults = furiousscanlib.SortByIP(scanResults)

	for _, result := range scanResults {
		openPortsStr := ""
		for i, port := range result.OpenPorts {
			if i > 0 {
				openPortsStr += ", "
			}
			openPortsStr += fmt.Sprintf("%d", port)
		}
		log.Info(fmt.Sprintf("%s (%s). Open ports: %s", result.IP, result.Name, openPortsStr))
	}

	// Thirdly, we shall attempt to connect to the ports and harvest SSL information
	log.Debug("Begin attempting to SSL connect to ports")

	// TODO: Remove test
	var certResults []scancertlib.CertScanResult
	for _, hostResult := range scanResults {
		for _, _ = range hostResult.OpenPorts {
			certResult := scancertlib.ScanCert(hostResult.IP.String(), 443)
			certResults = append(certResults, certResult)
		}
	}

	//certResults = []scancertlib.CertScanResult{}
	//for _, host := range []string{"tls-v1-2.badssl.com:1012", "tls-v1-1.badssl.com:1011", "tls-v1-0.badssl.com:1010"} {
	//	port, _ := strconv.Atoi(strings.Split(host, ":")[1])
	//	certResult := scancertlib.ScanCert(strings.Split(host, ":")[0], port)
	//	certResults = append(certResults, certResult)
	//}

	print("Finished")
	// Lastly, we shall export it

}
