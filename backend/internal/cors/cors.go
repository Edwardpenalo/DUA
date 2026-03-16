package cors

import (
	"net/http"
	"time"

	"dua/internal/scan"
)

func Analyze(targetURL string, timeout time.Duration) scan.CORSResult {
	started := time.Now()
	out := scan.CORSResult{Findings: []scan.CORSFinding{}}

	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodOptions, targetURL, nil)
	if err != nil {
		out.ExecutionTimeMs = time.Since(started).Milliseconds()
		return out
	}
	req.Header.Set("Origin", "https://example.org")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	req.Header.Set("User-Agent", "DUA-Scanner/0.2 cors-check")

	resp, err := client.Do(req)
	if err != nil {
		out.ExecutionTimeMs = time.Since(started).Milliseconds()
		return out
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := resp.Header.Get("Access-Control-Allow-Credentials") == "true"
	exploitable := false
	severity := "info"
	notes := "No obvious risky CORS pattern detected"

	switch {
	case allowOrigin == "*" && allowCreds:
		exploitable = true
		severity = "critical"
		notes = "Wildcard origin with credentials is insecure"
	case allowOrigin == "*":
		exploitable = true
		severity = "medium"
		notes = "Wildcard origin allows cross-site reads from any domain"
	case allowOrigin == "https://example.org" && allowCreds:
		exploitable = true
		severity = "high"
		notes = "Origin reflection detected with credentials enabled"
	case allowOrigin != "":
		severity = "low"
		notes = "CORS is enabled for a specific origin; validate allowlist policy"
	}

	out.Findings = append(out.Findings, scan.CORSFinding{
		URL:                 targetURL,
		AllowOrigin:         allowOrigin,
		AllowCredentials:    allowCreds,
		Exploitable:         exploitable,
		Severity:            severity,
		ExploitabilityNotes: notes,
	})

	out.ExecutionTimeMs = time.Since(started).Milliseconds()
	return out
}
