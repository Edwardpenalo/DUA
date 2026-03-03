package subdomain

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"dua/internal/scan"

	"golang.org/x/net/html"
)

// SubdomainOptions contains configuration for subdomain enumeration
type SubdomainOptions struct {
	Timeout            int    `json:"timeout_seconds"`
	PassiveOnly        bool   `json:"passive_only"`
	ActiveDNSBrute     bool   `json:"active_dns_brute"`
	CustomWordlist     string `json:"custom_wordlist_urls"`
	DNSResolver        string `json:"dns_resolver"`
	MaxConcurrency     int    `json:"max_concurrency"`
	ResolveSubdomains  bool   `json:"resolve_subdomains"`
	ProbeHTTP          bool   `json:"probe_http"`
	SkipWildcardDetect bool   `json:"skip_wildcard_detect"`
}

type Enumerator struct {
	opts SubdomainOptions
}

func New(opts SubdomainOptions) *Enumerator {
	if opts.Timeout <= 0 {
		opts.Timeout = 30
	}
	if opts.MaxConcurrency <= 0 {
		opts.MaxConcurrency = 50
	}
	if opts.DNSResolver == "" {
		opts.DNSResolver = "8.8.8.8:53"
	}
	return &Enumerator{opts: opts}
}

func (e *Enumerator) Run(ctx context.Context, target string) (*scan.SubdomainResult, error) {
	start := time.Now()
	log.Printf("[subdomain] Starting enumeration for %s", target)

	domain := extractDomain(target)
	result := &scan.SubdomainResult{Subdomains: []scan.SubdomainInfo{}}

	// Passive sources
	subs, _ := e.passiveEnumerate(ctx, domain)
	result.Subdomains = append(result.Subdomains, subs...)

	// Active DNS brute
	if !e.opts.PassiveOnly && e.opts.ActiveDNSBrute {
		bruteRes, _ := e.activeDNSBrute(ctx, domain)
		result.Subdomains = append(result.Subdomains, bruteRes...)
	}

	// Dedupe & resolve
	result.Subdomains = e.deduplicateAndResolve(ctx, result.Subdomains, domain)

	// HTTP probe
	if e.opts.ProbeHTTP {
		e.probeHTTP(ctx, result.Subdomains)
	}

	// Wildcard detection
	if !e.opts.SkipWildcardDetect {
		result.Wildcards = e.detectWildcards(ctx, domain, result.Subdomains)
	}

	result.Total = len(result.Subdomains)
	for _, sub := range result.Subdomains {
		if sub.Live {
			result.Live++
		}
	}

	result.ExecutionTimeMs = time.Since(start).Milliseconds()
	log.Printf("[subdomain] Enumeration completed: %d subdomains (%d live) in %dms",
		result.Total, result.Live, result.ExecutionTimeMs)

	return result, nil
}

func (e *Enumerator) passiveEnumerate(ctx context.Context, domain string) ([]scan.SubdomainInfo, error) {
	var results []scan.SubdomainInfo
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Source 1: CT logs
	wg.Add(1)
	go func() {
		defer wg.Done()
		subs := e.crtshEnumerate(ctx, domain)
		mu.Lock()
		for _, sub := range subs {
			results = append(results, scan.SubdomainInfo{Name: sub, Source: "crt.sh"})
		}
		mu.Unlock()
	}()

	// Source 2: DNS NS records
	wg.Add(1)
	go func() {
		defer wg.Done()
		subs := e.dnsNSEnumerate(ctx, domain)
		mu.Lock()
		for _, sub := range subs {
			results = append(results, scan.SubdomainInfo{Name: sub, Source: "dns_ns"})
		}
		mu.Unlock()
	}()

	wg.Wait()
	return results, nil
}

func (e *Enumerator) crtshEnumerate(ctx context.Context, domain string) []string {
	log.Printf("[subdomain] Querying CT logs for %s", domain)

	// Mock CT log data (in production, query crt.sh API)
	commonSubs := []string{
		"www", "mail", "ftp", "api", "admin", "blog",
		"shop", "cdn", "staging", "dev", "test", "portal",
	}

	var results []string
	for _, sub := range commonSubs {
		results = append(results, fmt.Sprintf("%s.%s", sub, domain))
	}
	return results
}

func (e *Enumerator) dnsNSEnumerate(ctx context.Context, domain string) []string {
	log.Printf("[subdomain] Querying NS records for %s", domain)

	resolver := &net.Resolver{PreferGo: true}
	nss, err := resolver.LookupNS(ctx, domain)
	if err != nil {
		log.Printf("[subdomain] NS lookup failed: %v", err)
		return nil
	}

	var results []string
	for _, ns := range nss {
		host := strings.TrimSuffix(ns.Host, ".")
		results = append(results, host)
	}
	return results
}

func (e *Enumerator) activeDNSBrute(ctx context.Context, domain string) ([]scan.SubdomainInfo, error) {
	log.Printf("[subdomain] Starting active DNS brute for %s", domain)

	// Small safe wordlist
	wordlist := []string{
		"www", "mail", "ftp", "smtp", "pop", "imap",
		"api", "admin", "blog", "shop", "store",
		"cdn", "static", "assets", "media", "images",
		"staging", "dev", "test", "qa", "demo",
		"portal", "app", "mobile", "m", "secure",
	}

	results := make([]scan.SubdomainInfo, 0)
	semaphore := make(chan struct{}, e.opts.MaxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	resolver := &net.Resolver{PreferGo: true}

	for _, prefix := range wordlist {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		subdomain := fmt.Sprintf("%s.%s", prefix, domain)
		wg.Add(1)
		semaphore <- struct{}{}

		go func(sub string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			ips, err := resolver.LookupHost(ctx, sub)
			if err == nil && len(ips) > 0 {
				mu.Lock()
				results = append(results, scan.SubdomainInfo{
					Name:   sub,
					IPv4:   ips,
					Source: "dns_brute",
				})
				mu.Unlock()
				log.Printf("[subdomain] Found: %s -> %v", sub, ips)
			}
		}(subdomain)
	}

	wg.Wait()
	return results, nil
}

func (e *Enumerator) deduplicateAndResolve(ctx context.Context, subs []scan.SubdomainInfo, baseDomain string) []scan.SubdomainInfo {
	seen := make(map[string]bool)
	var unique []scan.SubdomainInfo

	for _, sub := range subs {
		if seen[sub.Name] {
			continue
		}
		seen[sub.Name] = true
		unique = append(unique, sub)
	}

	if e.opts.ResolveSubdomains {
		resolver := &net.Resolver{PreferGo: true}
		for i := range unique {
			if len(unique[i].IPv4) == 0 && len(unique[i].IPv6) == 0 {
				ips, err := resolver.LookupHost(ctx, unique[i].Name)
				if err == nil {
					for _, ip := range ips {
						if net.ParseIP(ip).To4() != nil {
							unique[i].IPv4 = append(unique[i].IPv4, ip)
						} else {
							unique[i].IPv6 = append(unique[i].IPv6, ip)
						}
					}
				}
			}
		}
	}

	return unique
}

func (e *Enumerator) probeHTTP(ctx context.Context, subs []scan.SubdomainInfo) {
	log.Printf("[subdomain] Probing HTTP for %d subdomains", len(subs))

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	semaphore := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for i := range subs {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(idx int) {
			defer wg.Done()
			defer func() { <-semaphore }()

			target := subs[idx]
			schemes := []string{"https", "http"} // Try HTTPS first

			for _, scheme := range schemes {
				url := fmt.Sprintf("%s://%s", scheme, target.Name)
				resp, err := client.Get(url)
				if err != nil {
					continue
				}

				subs[idx].Live = true
				subs[idx].StatusCode = resp.StatusCode
				subs[idx].Title = extractTitle(resp)
				subs[idx].ContentType = resp.Header.Get("Content-Type")
				subs[idx].ServerHeader = resp.Header.Get("Server")
				subs[idx].Fingerprint = hashResponse(resp)
				resp.Body.Close()
				break // Found working scheme
			}
		}(i)
	}

	wg.Wait()
}

func (e *Enumerator) detectWildcards(ctx context.Context, domain string, subs []scan.SubdomainInfo) []string {
	log.Printf("[subdomain] Detecting wildcards for %s", domain)

	resolver := &net.Resolver{PreferGo: true}

	// Try multiple random subdomains to confirm wildcard
	randomTests := []string{
		fmt.Sprintf("nonexistent%d.%s", time.Now().UnixNano()%10000, domain),
		fmt.Sprintf("random%d.%s", time.Now().UnixNano()%10000, domain),
		fmt.Sprintf("test%d.%s", time.Now().UnixNano()%10000, domain),
	}

	var wildcardIPs []string
	wildcardDetected := false

	for _, testSub := range randomTests {
		ips, err := resolver.LookupHost(ctx, testSub)
		if err == nil && len(ips) > 0 {
			wildcardDetected = true
			wildcardIPs = append(wildcardIPs, ips...)
			log.Printf("[subdomain] Wildcard detected: %s -> %v", testSub, ips)
		}
	}

	if wildcardDetected {
		// Deduplicate IPs
		seen := make(map[string]bool)
		var unique []string
		for _, ip := range wildcardIPs {
			if !seen[ip] {
				seen[ip] = true
				unique = append(unique, ip)
			}
		}
		return unique
	}

	return nil
}

func extractDomain(target string) string {
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	target = strings.Split(target, "/")[0]
	target = strings.Split(target, ":")[0]
	return target
}

func extractTitle(resp *http.Response) string {
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return ""
	}

	var title string
	var findTitle func(*html.Node)
	findTitle = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "title" {
			if n.FirstChild != nil {
				title = strings.TrimSpace(n.FirstChild.Data)
			}
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if title == "" {
				findTitle(c)
			}
		}
	}
	findTitle(doc)
	return title
}

func hashResponse(resp *http.Response) string {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	hash := md5.Sum(body)
	return fmt.Sprintf("%x", hash)
}
