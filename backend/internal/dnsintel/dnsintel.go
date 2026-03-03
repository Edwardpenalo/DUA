package dnsintel

import (
	"net"
	"sort"
	"strings"

	"dua/internal/scan"
)

func Resolve(target string) scan.DNSReport {
	host := sanitizeHost(target)

	rep := scan.DNSReport{
		Target:   target,
		Hostname: host,
	}

	// If it's an IP, still try reverse PTR and exit early
	if ip := net.ParseIP(host); ip != nil {
		rep.IPs = []string{ip.String()}
		rep.ReversePTR = append(rep.ReversePTR, reverse(ip.String()))
		return rep
	}

	// A/AAAA
	if ips, err := net.LookupIP(host); err == nil {
		for _, ip := range ips {
			rep.IPs = append(rep.IPs, ip.String())
		}
		rep.IPs = dedupe(rep.IPs)
		sort.Strings(rep.IPs)
	}

	// CNAME (may fail if none)
	if cn, err := net.LookupCNAME(host); err == nil && cn != "" {
		// net.LookupCNAME returns the canonical name (may be same as host)
		cn = strings.TrimSuffix(cn, ".")
		if !strings.EqualFold(cn, host) {
			rep.CNAME = dedupe(append(rep.CNAME, cn))
		}
	}

	// MX
	if mxs, err := net.LookupMX(host); err == nil {
		for _, mx := range mxs {
			rep.MX = append(rep.MX, scan.DNSMXRecord{
				Host: strings.TrimSuffix(mx.Host, "."),
				Pref: mx.Pref,
			})
		}
		sort.Slice(rep.MX, func(i, j int) bool {
			if rep.MX[i].Pref == rep.MX[j].Pref {
				return rep.MX[i].Host < rep.MX[j].Host
			}
			return rep.MX[i].Pref < rep.MX[j].Pref
		})
	}

	// NS
	if nss, err := net.LookupNS(host); err == nil {
		for _, ns := range nss {
			rep.NS = append(rep.NS, strings.TrimSuffix(ns.Host, "."))
		}
		rep.NS = dedupe(rep.NS)
		sort.Strings(rep.NS)
	}

	// Reverse PTR for every resolved IP (limit to avoid abuse)
	maxPTR := 10
	for i, ip := range rep.IPs {
		if i >= maxPTR {
			break
		}
		rep.ReversePTR = append(rep.ReversePTR, reverse(ip))
	}

	return rep
}

func reverse(ip string) scan.DNSPTR {
	out := scan.DNSPTR{IP: ip}
	names, err := net.LookupAddr(ip)
	if err != nil {
		return out
	}
	for _, n := range names {
		n = strings.TrimSuffix(n, ".")
		out.PTR = append(out.PTR, n)
	}
	out.PTR = dedupe(out.PTR)
	sort.Strings(out.PTR)
	return out
}

func sanitizeHost(target string) string {
	t := strings.TrimSpace(target)
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "https://")
	t = strings.Split(t, "/")[0]
	t = strings.TrimSpace(t)
	return t
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
