package scancertlib

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	log "github.com/sirupsen/logrus"
)

type CertScanResult struct {
	Host           string
	Port           int
	SSL			   bool
	//Valid          bool
	//CertIssuerOrg  []string
	//CertIssuance   time.Time
	//CertExpiry     time.Time
	//CertCommonName string
	//CertSAN        []string
	Certs			[]*x509.Certificate
}

func ScanCert(host string, port int) CertScanResult {
	result := CertScanResult{
		Host:  host,
		Port:  port,
		SSL: false,
		Certs: []*x509.Certificate{},
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), conf)
	if err != nil {
		log.Error(err)
		return result
	}
	defer conn.Close()
	result.SSL = true

	certsPointers := conn.ConnectionState().PeerCertificates
	if len(certsPointers) == 0 {
		log.Warning(fmt.Sprintf("No certificate received on %s:%d", host, port))
		return result
	}

	result.Certs = certsPointers

	return result
}
