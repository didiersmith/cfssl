package scan

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"strings"

	"github.com/cloudflare/cfssl/log"
)

// HTTPS contains scanners to test application layer HTTP(S) features
var HTTPS = &Family{
	Name:        "HTTPS",
	Description: "Scans for application layer HTTP(S) features",
	Scanners: []*Scanner{
		{
			"HPKP",
			"Host serves valid HPKP headers",
			hpkpScan,
		},
		{
			"HSTS",
			"Host serves valid HSTS header",
			hstsScan,
		},
	},
}

// fingerprints contains the public key SHA-256 fingerprints for host's pinning.
type fingerprint string

func (f fingerprint) String() string {
	return string(f)
}

func (f fingerprint) Describe() string {
	return "Public key SHA-256 fingerprints for a host"
}

// hpkpScan tests that the host serves correct HPKP headers.
func hpkpScan(host string) (grade Grade, output Output, err error) {
	var cert *x509.Certificate
	tr := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := tls.DialWithDialer(Dialer, network, addr, defaultTLSConfig(host))
			if err == nil {
				cert = conn.ConnectionState().PeerCertificates[0]
			}
			return conn, err
		},
	}
	client := http.Client{Transport: tr}
	resp, err := client.Get("https://" + host)
	if err != nil {
		return
	}
	hpkpHeader := resp.Header.Get("Public-Key-Pins")
	if hpkpHeader != "" {
		log.Debug(hpkpHeader)
		digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		fing := base64.StdEncoding.EncodeToString(digest[:])
		if strings.Contains(hpkpHeader, fing) {
			output = fingerprint(fing)
			grade = Good
		}
	}
	return
}

// hstsScan tests that the host serves correct HPKP headers.
func hstsScan(host string) (grade Grade, output Output, err error) {
	resp, err := http.Get("https://" + host)
	if err != nil {
		return
	}
	hstsHeader := resp.Header.Get("Strict-Transport-Security")
	if hstsHeader != "" {
		log.Debug(hstsHeader)
		grade = Good
	}
	return
}
