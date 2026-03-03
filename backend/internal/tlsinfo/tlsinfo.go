package tlsinfo

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"dua/internal/scan"
)

type Options struct {
	Timeout time.Duration
}

func Inspect(host string, port int, opt Options) (*scan.TLSFinding, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 2 * time.Second
	}

	host = sanitizeHost(host)
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	d := &net.Dialer{Timeout: opt.Timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // recon only
		ServerName:         host,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return &scan.TLSFinding{
			Port:       port,
			ServerName: host,
			Expired:    false,
		}, nil
	}

	leaf := cs.PeerCertificates[0]
	days := int(time.Until(leaf.NotAfter).Hours() / 24)

	f := &scan.TLSFinding{
		Port:          port,
		ServerName:    host,
		SubjectCN:     leaf.Subject.CommonName,
		SANs:          extractSANs(leaf),
		IssuerCN:      leaf.Issuer.CommonName,
		NotBefore:     leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining: days,
		Expired:       time.Now().After(leaf.NotAfter),
		TLSVersion:    tlsVersionString(cs.Version),
		CipherSuite:   tls.CipherSuiteName(cs.CipherSuite),
	}

	return f, nil
}

func extractSANs(cert *x509.Certificate) []string {
	var out []string
	out = append(out, cert.DNSNames...)
	// IP SANs
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func sanitizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.Split(host, "/")[0]
	return host
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}
