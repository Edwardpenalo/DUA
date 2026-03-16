package injections

import (
	"net/url"
	"strings"
	"time"

	"dua/internal/scan"
)

func Analyze(pageURL, htmlSnippet string) scan.InjectionSignalsResult {
	started := time.Now()
	out := scan.InjectionSignalsResult{
		SQLiSignals: []scan.InjectionSignal{},
		XSSSignals:  []scan.InjectionSignal{},
	}

	u, err := url.Parse(pageURL)
	if err != nil {
		out.ExecutionTimeMs = time.Since(started).Milliseconds()
		return out
	}

	for key, vals := range u.Query() {
		for _, v := range vals {
			if strings.TrimSpace(v) == "" {
				continue
			}
			if strings.Contains(htmlSnippet, v) {
				out.XSSSignals = append(out.XSSSignals, scan.InjectionSignal{
					URL:        pageURL,
					Parameter:  key,
					Type:       "xss",
					Confidence: "low",
					Evidence:   "parameter value reflected in response HTML",
					Payload:    v,
				})
			}

			if hasSQLiPattern(v) {
				out.SQLiSignals = append(out.SQLiSignals, scan.InjectionSignal{
					URL:        pageURL,
					Parameter:  key,
					Type:       "sqli",
					Confidence: "low",
					Evidence:   "parameter contains SQL-like control characters/pattern",
					Payload:    v,
				})
			}
		}
	}

	out.ExecutionTimeMs = time.Since(started).Milliseconds()
	return out
}

func hasSQLiPattern(v string) bool {
	lower := strings.ToLower(v)
	patterns := []string{"'", "--", "/*", " or ", " and ", "union", "select", "sleep("}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
