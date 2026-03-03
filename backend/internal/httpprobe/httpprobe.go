package httpprobe

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type Result struct {
	URL         string
	FinalURL    string
	Status      int
	Title       string
	Headers     map[string]string
	BodySnippet string
}

func Run(target string, timeout time.Duration, maxRedirects int) (*Result, error) {
	candidateURLs := buildCandidates(target)

	var lastErr error
	for _, u := range candidateURLs {
		res, err := probeURL(u, timeout, maxRedirects)
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no candidates attempted")
	}
	return nil, lastErr
}

func buildCandidates(target string) []string {
	t := strings.TrimSpace(target)
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "https://")

	return []string{
		"https://" + t,
		"http://" + t,
	}
}

func probeURL(url string, timeout time.Duration, maxRedirects int) (*Result, error) {
	redirects := 0

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10},
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirects++
			if redirects > maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "DUA-Scanner/0.1 (stateless)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read a limited amount to avoid huge pages
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 300_000))
	bodyStr := string(body)

	title := extractTitle(bodyStr)

	// Keep only a snippet for fingerprinting (avoid huge memory usage)
	snippet := bodyStr
	if len(snippet) > 20000 {
		snippet = snippet[:20000]
	}

	headers := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &Result{
		URL:         url,
		FinalURL:    resp.Request.URL.String(),
		Status:      resp.StatusCode,
		Title:       title,
		Headers:     headers,
		BodySnippet: snippet,
	}, nil
}

func extractTitle(html string) string {
	l := strings.ToLower(html)
	start := strings.Index(l, "<title")
	if start == -1 {
		return ""
	}
	gt := strings.Index(l[start:], ">")
	if gt == -1 {
		return ""
	}
	gt = start + gt + 1
	end := strings.Index(l[gt:], "</title>")
	if end == -1 {
		return ""
	}
	raw := html[gt : gt+end]
	return strings.TrimSpace(strings.ReplaceAll(raw, "\n", " "))
}
