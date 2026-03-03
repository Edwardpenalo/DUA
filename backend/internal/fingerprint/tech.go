package fingerprint

import (
	"regexp"
	"strings"

	"dua/internal/scan"
)

var metaGeneratorRe = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)

func FromHTTP(headers map[string]string, html string) []scan.TechFinding {
	var out []scan.TechFinding

	// Server header
	if v, ok := headers["Server"]; ok && strings.TrimSpace(v) != "" {
		out = append(out, scan.TechFinding{
			Name:       normalizeTech(v),
			Confidence: 80,
			Evidence:   "header: Server=" + v,
		})
	}

	// X-Powered-By
	if v, ok := headers["X-Powered-By"]; ok && strings.TrimSpace(v) != "" {
		out = append(out, scan.TechFinding{
			Name:       normalizeTech(v),
			Confidence: 85,
			Evidence:   "header: X-Powered-By=" + v,
		})
	}

	// Cookie-based signals
	if v, ok := headers["Set-Cookie"]; ok && v != "" {
		c := strings.ToLower(v)
		addCookieTech := func(name, token string) {
			if strings.Contains(c, strings.ToLower(token)) {
				out = append(out, scan.TechFinding{
					Name:       name,
					Confidence: 80,
					Evidence:   "cookie: " + token,
				})
			}
		}
		addCookieTech("php", "PHPSESSID")
		addCookieTech("asp.net", "ASP.NET_SessionId")
		addCookieTech("moodle", "MoodleSession")
		addCookieTech("wordpress", "wordpress_logged_in")
	}

	// Meta generator
	if html != "" {
		if m := metaGeneratorRe.FindStringSubmatch(html); len(m) == 2 {
			gen := strings.TrimSpace(m[1])
			if gen != "" {
				out = append(out, scan.TechFinding{
					Name:       normalizeTech(gen),
					Confidence: 90,
					Evidence:   "html: meta generator=" + gen,
				})
			}
		}
	}

	// Simple HTML path hints
	hl := strings.ToLower(html)
	addHint := func(name, hint string, confidence int) {
		if strings.Contains(hl, hint) {
			out = append(out, scan.TechFinding{
				Name:       name,
				Confidence: confidence,
				Evidence:   "html: contains " + hint,
			})
		}
	}
	addHint("wordpress", "/wp-content/", 85)
	addHint("drupal", "/sites/default/", 85)
	addHint("joomla", "/components/", 70)
	addHint("moodle", "/theme/", 60)

	return dedupe(out)
}

func normalizeTech(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	// keep it short-ish
	if i := strings.IndexAny(s, " ;("); i > 0 {
		return s[:i]
	}
	return s
}

func dedupe(in []scan.TechFinding) []scan.TechFinding {
	seen := map[string]bool{}
	var out []scan.TechFinding
	for _, f := range in {
		key := f.Name + "|" + f.Evidence
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}
