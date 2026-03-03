package secheaders

import (
	"sort"
	"strings"

	"dua/internal/scan"
)

func Analyze(h map[string]string) scan.HeadersReport {
	// normalize keys to lower
	n := map[string]string{}
	for k, v := range h {
		n[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}

	var findings []scan.HeaderFinding
	score := 100
	var recs []string

	addMissing := func(name, sev string, points int, rec string) {
		findings = append(findings, scan.HeaderFinding{
			Name:     name,
			Status:   "missing",
			Severity: sev,
		})
		score -= points
		if rec != "" {
			recs = append(recs, rec)
		}
	}

	addPresent := func(name, sev, evidence string) {
		findings = append(findings, scan.HeaderFinding{
			Name:     name,
			Status:   "present",
			Severity: sev,
			Evidence: evidence,
		})
	}

	addWeak := func(name, sev string, points int, evidence, rec string) {
		findings = append(findings, scan.HeaderFinding{
			Name:     name,
			Status:   "weak",
			Severity: sev,
			Evidence: evidence,
		})
		score -= points
		if rec != "" {
			recs = append(recs, rec)
		}
	}

	// HSTS
	if v, ok := n["strict-transport-security"]; !ok || v == "" {
		addMissing("Strict-Transport-Security", "high", 25, "Enable HSTS on HTTPS sites (e.g., Strict-Transport-Security: max-age=15552000; includeSubDomains; preload).")
	} else {
		vl := strings.ToLower(v)
		addPresent("Strict-Transport-Security", "info", v)
		if !strings.Contains(vl, "max-age=") {
			addWeak("Strict-Transport-Security", "medium", 8, v, "HSTS should include a max-age directive.")
		}
	}

	// CSP
	if v, ok := n["content-security-policy"]; !ok || v == "" {
		addMissing("Content-Security-Policy", "high", 25, "Define a Content Security Policy to mitigate XSS (start with default-src 'self' and iterate).")
	} else {
		vl := strings.ToLower(v)
		addPresent("Content-Security-Policy", "info", v)
		// weak patterns
		if strings.Contains(vl, "unsafe-inline") || strings.Contains(vl, "unsafe-eval") {
			addWeak("Content-Security-Policy", "medium", 10, v, "Avoid 'unsafe-inline'/'unsafe-eval' in CSP when possible.")
		}
	}

	// X-Frame-Options (legacy) / frame-ancestors (CSP)
	if v, ok := n["x-frame-options"]; !ok || v == "" {
		// If CSP has frame-ancestors, we can downgrade severity
		if csp, ok := n["content-security-policy"]; ok && strings.Contains(strings.ToLower(csp), "frame-ancestors") {
			addPresent("X-Frame-Options", "info", "not set (covered by CSP frame-ancestors)")
		} else {
			addMissing("X-Frame-Options", "medium", 10, "Set X-Frame-Options to DENY or SAMEORIGIN (or use CSP frame-ancestors).")
		}
	} else {
		vl := strings.ToLower(v)
		addPresent("X-Frame-Options", "info", v)
		if vl != "deny" && vl != "sameorigin" {
			addWeak("X-Frame-Options", "low", 3, v, "Use DENY or SAMEORIGIN for X-Frame-Options.")
		}
	}

	// X-Content-Type-Options
	if v, ok := n["x-content-type-options"]; !ok || v == "" {
		addMissing("X-Content-Type-Options", "low", 5, "Set X-Content-Type-Options: nosniff.")
	} else {
		addPresent("X-Content-Type-Options", "info", v)
		if strings.ToLower(v) != "nosniff" {
			addWeak("X-Content-Type-Options", "low", 2, v, "X-Content-Type-Options should be 'nosniff'.")
		}
	}

	// Referrer-Policy
	if v, ok := n["referrer-policy"]; !ok || v == "" {
		addMissing("Referrer-Policy", "low", 5, "Set Referrer-Policy (e.g., strict-origin-when-cross-origin).")
	} else {
		addPresent("Referrer-Policy", "info", v)
	}

	// Permissions-Policy
	if v, ok := n["permissions-policy"]; !ok || v == "" {
		addMissing("Permissions-Policy", "low", 5, "Set Permissions-Policy to restrict powerful browser features (camera, microphone, geolocation, etc.).")
	} else {
		addPresent("Permissions-Policy", "info", v)
	}

	// Cross-Origin headers (modern hardening)
	if v, ok := n["cross-origin-opener-policy"]; !ok || v == "" {
		addMissing("Cross-Origin-Opener-Policy", "low", 3, "Consider COOP (e.g., same-origin) to improve isolation.")
	} else {
		addPresent("Cross-Origin-Opener-Policy", "info", v)
	}
	if v, ok := n["cross-origin-resource-policy"]; !ok || v == "" {
		addMissing("Cross-Origin-Resource-Policy", "low", 3, "Consider CORP (e.g., same-site) to reduce cross-origin data leaks.")
	} else {
		addPresent("Cross-Origin-Resource-Policy", "info", v)
	}

	if score < 0 {
		score = 0
	}

	// stable ordering
	sort.Slice(findings, func(i, j int) bool { return findings[i].Name < findings[j].Name })
	recs = dedupe(recs)

	return scan.HeadersReport{
		Score:           score,
		Findings:        findings,
		Recommendations: recs,
	}
}

func dedupe(in []string) []string {
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
