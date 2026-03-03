package direnum

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"dua/internal/scan"
)

type Options struct {
	Timeout         time.Duration
	Concurrency     int
	MaxPaths        int // hard cap para no destruirte la RAM
	FollowRedirects bool
}

var hrefSrcRe = regexp.MustCompile(`(?i)(href|src)=["']([^"'#?]+)`)

var commonWordlist = []string{
	"/admin", "/administrator", "/login", "/signin", "/auth", "/dashboard",
	"/wp-admin", "/wp-login.php", "/xmlrpc.php", "/wp-json",
	"/user", "/users", "/account", "/profile",
	"/api", "/api/v1", "/swagger", "/swagger/index.html", "/openapi.json",
	"/robots.txt", "/sitemap.xml",
	"/.git/", "/.env", "/config", "/backup", "/backups", "/old", "/dev", "/test", "/staging",
}

func Run(baseURL string, headers map[string]string, htmlSnippet string, opt Options) ([]scan.DirFinding, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 10 * time.Second
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = 25
	}
	if opt.MaxPaths <= 0 {
		opt.MaxPaths = 300
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	// Build candidate paths from:
	// 1) HTML discovery
	// 2) robots + sitemap (active but non-intrusive)
	// 3) common wordlist
	candidates := make(map[string]scan.DirFinding)

	// From HTML (discovered)
	for _, p := range extractPathsFromHTML(htmlSnippet) {
		if !strings.HasPrefix(p, "/") {
			continue
		}
		candidates[p] = scan.DirFinding{URL: join(u, p), Kind: "discovered", Evidence: "html"}
	}

	// robots + sitemap as "special" (always worth checking)
	candidates["/robots.txt"] = scan.DirFinding{URL: join(u, "/robots.txt"), Kind: "robots", Evidence: "seed"}
	candidates["/sitemap.xml"] = scan.DirFinding{URL: join(u, "/sitemap.xml"), Kind: "sitemap", Evidence: "seed"}

	// Wordlist
	for _, p := range commonWordlist {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if _, ok := candidates[p]; !ok {
			candidates[p] = scan.DirFinding{URL: join(u, p), Kind: "wordlist", Evidence: "common"}
		}
	}

	// Hard cap
	paths := make([]scan.DirFinding, 0, len(candidates))
	for _, v := range candidates {
		paths = append(paths, v)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].URL < paths[j].URL })
	if len(paths) > opt.MaxPaths {
		paths = paths[:opt.MaxPaths]
	}

	client := &http.Client{
		Timeout: opt.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if opt.FollowRedirects {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}

	type result struct {
		f  scan.DirFinding
		ok bool
	}

	ctx, cancel := context.WithTimeout(context.Background(), opt.Timeout+5*time.Second)
	defer cancel()

	in := make(chan scan.DirFinding)
	out := make(chan result)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for f := range in {
			status, ok := headOrGet(ctx, client, f.URL)
			if ok {
				f.Status = status
				out <- result{f: f, ok: true}
			}
		}
	}

	wg.Add(opt.Concurrency)
	for i := 0; i < opt.Concurrency; i++ {
		go worker()
	}

	go func() {
		defer close(in)
		for _, f := range paths {
			select {
			case <-ctx.Done():
				return
			case in <- f:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	// Keep only meaningful results (200-399, 401,403)
	var findings []scan.DirFinding
	for r := range out {
		if !r.ok {
			continue
		}
		s := r.f.Status
		if (s >= 200 && s <= 399) || s == 401 || s == 403 {
			findings = append(findings, r.f)
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Status == findings[j].Status {
			return findings[i].URL < findings[j].URL
		}
		return findings[i].Status < findings[j].Status
	})

	return findings, nil
}

func extractPathsFromHTML(html string) []string {
	matches := hrefSrcRe.FindAllStringSubmatch(html, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) != 3 {
			continue
		}
		val := strings.TrimSpace(m[2])
		// keep only same-site relative paths
		if strings.HasPrefix(val, "/") && !strings.HasPrefix(val, "//") {
			out = append(out, val)
		}
	}
	return dedupeStrings(out)
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func join(base *url.URL, path string) string {
	u := *base
	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func headOrGet(ctx context.Context, client *http.Client, url string) (int, bool) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	req.Header.Set("User-Agent", "DUA-Scanner/0.1 (stateless)")

	resp, err := client.Do(req)
	if err == nil && resp != nil {
		defer resp.Body.Close()
		// Some servers don’t support HEAD correctly
		if resp.StatusCode == 405 || resp.StatusCode == 501 {
			return getStatus(ctx, client, url)
		}
		return resp.StatusCode, true
	}
	return getStatus(ctx, client, url)
}

func getStatus(ctx context.Context, client *http.Client, url string) (int, bool) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "DUA-Scanner/0.1 (stateless)")
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return 0, false
	}
	defer resp.Body.Close()
	return resp.StatusCode, true
}
