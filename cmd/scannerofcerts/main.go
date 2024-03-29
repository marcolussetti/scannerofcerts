package main

// scannerofcerts is a portable Go application that scans for, and reports on,
// certificates in a specified subnet.
//
// It scan each host in the subnet on a customizable range of ports, aiming to
// discover hosts you may have well forgotten the configuration of.
// It will then group the hosts by certificate, and report on the certificate's
// validity, expiration date, and applicable hosts/ports combinations.

import (
	"context"
	"crypto/md5"
	"encoding/csv"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"scannerofcerts/internal/furiousscanlib"
	"scannerofcerts/internal/scancertlib"
	"strconv"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
)

var (
	logLevel = log.DebugLevel
)

func parsePortsArg(input string) ([]int, error) {
	var ports []int
	for _, targetPort := range strings.Split(input, ",") {
		if strings.Contains(targetPort, ":") {
			portRangeStr := strings.Split(targetPort, ":")
			var portRangeInt []int
			if len(portRangeStr) != 2 {
				log.Error(errors.New("incorrect range in port range"))
			} else {
				portRangeItem, _ := strconv.Atoi(portRangeStr[0])
				portRangeInt = append(portRangeInt, portRangeItem)
				portRangeItem, _ = strconv.Atoi(portRangeStr[1])
				portRangeInt = append(portRangeInt, portRangeItem)
				for i := portRangeInt[0]; i <= portRangeInt[1]; i++ {
					if i > 65535 || i < 0 {
						log.Error(errors.New("port exceeds valid values for TCP ports"))
					} else {
						ports = append(ports, i)
					}
				}
			}
		} else {
			portInt, err := strconv.Atoi(targetPort)
			if err != nil {
				log.Error(err)
			} else if portInt > 65535 || portInt < 0 {
				log.Error(errors.New("port exceeds valid values for TCP ports"))
			} else {
				ports = append(ports, portInt)
			}
		}
	}

	if len(ports) < 1 {
		return ports, errors.New("no valid ports parsed")
	}

	return ports, nil
}

func ptrLookup(ip string) string {
	netResolverCtx, cancel := context.WithTimeout(context.TODO(), 500*time.Millisecond)
	defer cancel()
	var netResolver net.Resolver

	dnsNames, _ := netResolver.LookupAddr(netResolverCtx, ip)
	dnsName := ""
	if len(dnsNames) > 0 {
		dnsName = dnsNames[0]
	}

	// Golang rather punctiliously insists on supplying FQDNs which have, as is certainly correct, a terminating dot.
	// It is however unclear whether anyone else cares.
	if strings.HasSuffix(dnsName, ".") {
		dnsName = strings.TrimRight(dnsName, ".")
	}

	return dnsName
}

func scan(c *cli.Context) error {
	// Firstly, we shall handle flags, initial setup, and so forth
	log.SetLevel(logLevel)

	// TODO: consider if we ought to provide a fallback to a non-privileged TCP/Connect scan method
	if os.Getuid() > 0 {
		log.Error("scannerofcerts requires root privileges to be able to port scan. Thank you for your understanding.")
		os.Exit(1)
	}

	// Second, extract flags
	targetsHosts := c.String("targets")
	targets := strings.Split(targetsHosts, ",")
	targetPorts := c.String("ports")
	ports, err := parsePortsArg(targetPorts)
	if err != nil {
		log.Fatalf("no valid ports parsed")
	}
	scanParallelism := c.Int("parallelism")
	scanTimeout := time.Duration(c.Int("timeout")) * time.Millisecond

	// Secondly, we shall scan the hosts given to determine which ports to further investigate
	log.Debug("Begin furious-backed port scan")
	var scanResults []furiousscanlib.PortScanHost
	for _, targetRange := range targets {
		scanResults = append(scanResults, furiousscanlib.PortScan(targetRange, ports, scanTimeout, scanParallelism)...)
	}
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

	var certResults []scancertlib.CertScanResult
	for _, hostResult := range scanResults {
		for _, port := range hostResult.OpenPorts {
			certResult := scancertlib.ScanCert(hostResult.IP.String(), port)
			certResults = append(certResults, certResult)
		}
	}

	log.Debug("Scan finished")

	// Lastly, we shall export it
	log.Debug("Export started")
	// It is often found convenient to have a DNS name associated with an IP, but a timeout is desirable on resolution

	output := [][]string{
		{"host", "dns_name", "port", "fingerprint", "valid_not_before", "valid_not_after", "subject", "issuer", "sans"},
	}
	for _, certResult := range certResults {
		dnsName := ptrLookup(certResult.Host)

		// If no certificates are found, we shall simply append the host on its own
		if len(certResult.Certs) == 0 {
			output = append(output, []string{certResult.Host, dnsName, fmt.Sprintf("%d", certResult.Port), ""})
			continue
		}
		leafCert := certResult.Certs[0]

		leafFingerprint := ""
		for _, chunk := range md5.Sum(leafCert.Raw) {
			leafFingerprint += fmt.Sprintf("%02X", chunk)
		}

		leafSAN := ""
		for _, san := range leafCert.DNSNames {
			leafSAN += fmt.Sprintf(",%s", san)
		}
		for _, san := range leafCert.IPAddresses {
			leafSAN += fmt.Sprintf(",%s", san)
		}
		if len([]rune(leafSAN)) > 0 {
			leafSAN = string([]rune(leafSAN)[1:len([]rune(leafSAN))])
		}

		output = append(output, []string{certResult.Host, dnsName, fmt.Sprintf("%d", certResult.Port), leafFingerprint,
			leafCert.NotBefore.Format("2006-01-02"), leafCert.NotAfter.Format("2006-01-02"),
			fmt.Sprintf("CN=%s, OU=%s, O=%s", leafCert.Subject.CommonName, leafCert.Subject.OrganizationalUnit,
				leafCert.Subject.Organization),
			fmt.Sprintf("CN=%s, OU=%s, O=%s", leafCert.Issuer.CommonName, leafCert.Issuer.OrganizationalUnit,
				leafCert.Issuer.Organization),
			leafSAN,
		})
	}

	var csvOutputs []*os.File
	var csvWriters []*csv.Writer
	if len(c.String("csv")) > 0 {
		csvOutput, err := os.Create(c.String("csv"))
		if err != nil {
			log.Fatal("Failed to create target file - ", err)
		}
		csvOutputs = append(csvOutputs, csvOutput)
	}
	if len(c.String("csv")) == 0 || c.Bool("stdout") {
		csvOutputs = append(csvOutputs, os.Stdout)
	}
	for _, csvOutput := range csvOutputs {
		csvWriters = append(csvWriters, csv.NewWriter(csvOutput))
	}

	for _, entry := range output {
		for _, csvWriter := range csvWriters {
			if err := csvWriter.Write(entry); err != nil {
				log.Error("Could not write CSV - ", err)
			}
		}
	}

	for _, csvWriter := range csvWriters {
		csvWriter.Flush()
		if err := csvWriter.Error(); err != nil {
			log.Error(err)
		}
	}
	for _, csvOutput := range csvOutputs {
		csvOutput.Close()
	}

	log.Debug("Export completed")

	return nil

}

func main() {
	app := &cli.App{
		Name:  "scannerofcerts",
		Usage: "Scan and reports on certificate in a IP range or hostlist",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "targets",
				Aliases:  []string{"t"},
				Usage:    "host or list of host/ranges to be scanned. Multiple hosts may be separated by commas, ranges can be specified with subnets (e.g. 10.10.10.0/24)",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "ports",
				Aliases: []string{"p"},
				Usage:   "list of comma-separated ports to scan. : can be used to indicate ranges",
				Value:   "21,22,25,110,119,143,389,433,443,465,563,585,636,853,981,989,990,992,993,994,995,1311,1443,1521,2083,2087,2096,2443,2484,3269,3443,4443,5061,5443,5986,6443,6679,6697,7002,7443,8443,8888,9443",
			},
			&cli.StringFlag{
				Name:  "csv",
				Usage: "path to output for CSV file, disables stdout",
				//Required: true,
			},
			&cli.BoolFlag{
				Name:  "stdout",
				Usage: "prints output to stdout, implied if other output methods are not enabled",
				//Required: true,
			},
			&cli.IntFlag{
				Name:  "timeout",
				Usage: "timeout (in ms) for the port scan",
				Value: 20000,
			},
			&cli.IntFlag{
				Name:  "parallelism",
				Usage: "parallelism level for the port scan",
				Value: 2000,
			},
		},
		Action: scan,
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
