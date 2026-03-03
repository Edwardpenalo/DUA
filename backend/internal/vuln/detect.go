package vuln

import (
	"regexp"
	"strings"

	"dua/internal/scan"
)

// Detecciones básicas desde headers + HTML snippet (sin crawling).
// V2: agregaremos scraping no intrusivo (robots/sitemap/wp-json) con límites.

var reGenerator = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
var reJQuery = regexp.MustCompile(`(?i)jquery(?:\.min)?\.js(?:\?ver=|\-)(\d+\.\d+\.\d+)`)
var reWordPressVer = regexp.MustCompile(`(?i)wordpress\s+(\d+\.\d+(\.\d+)?)`)
var reMoodleVer = regexp.MustCompile(`(?i)moodle\s+(\d+\.\d+(\.\d+)?)`)

func DetectComponents(out scan.Result, htmlSnippet string) []scan.Component {
	var comps []scan.Component

	// 1) From HTTP headers: Server / X-Powered-By (good evidence)
	if out.HTTP != nil {
		if v := header(out.HTTP.Headers, "Server"); v != "" {
			comps = append(comps, scan.Component{
				Name:       normalizeServerName(v),
				Version:    extractLooseVersion(v),
				Confidence: "likely",
				Evidence:   "header: Server=" + v,
			})
		}
		if v := header(out.HTTP.Headers, "X-Powered-By"); v != "" {
			// Sometimes includes ASP.NET / PHP
			name := normalizePoweredBy(v)
			comps = append(comps, scan.Component{
				Name:       name,
				Version:    extractLooseVersion(v),
				Confidence: "likely",
				Evidence:   "header: X-Powered-By=" + v,
			})
			// If it's ASP.NET, map to NuGet ecosystem later only if we have a real package name (often we don't).
		}
	}

	// 2) From CMS detector output (your cms module)
	for _, c := range out.CMS {
		switch strings.ToLower(c.Name) {
		case "wordpress":
			comp := scan.Component{
				Name:       "wordpress",
				Confidence: confidenceFromPct(c.Confidence),
				Evidence:   "cms: wordpress (confidence " + itoa(c.Confidence) + ")",
			}
			// Try to extract version from HTML snippet (meta generator etc.)
			if v := guessCMSVersion("wordpress", htmlSnippet); v != "" {
				comp.Version = v
				comp.Confidence = "confirmed"
				comp.Evidence = comp.Evidence + "; html: generator/version"
			}
			// OSV ecosystem for WordPress is not reliably covered → we keep as component for reporting.
			comps = append(comps, comp)

		case "moodle":
			comp := scan.Component{
				Name:       "moodle",
				Confidence: confidenceFromPct(c.Confidence),
				Evidence:   "cms: moodle (confidence " + itoa(c.Confidence) + ")",
			}
			if v := guessCMSVersion("moodle", htmlSnippet); v != "" {
				comp.Version = v
				comp.Confidence = "confirmed"
				comp.Evidence = comp.Evidence + "; html: generator/version"
			}
			comps = append(comps, comp)
		}
	}

	// 3) From HTML: generator meta + jQuery version
	if m := reGenerator.FindStringSubmatch(htmlSnippet); len(m) == 2 {
		gen := strings.TrimSpace(m[1])
		// Sometimes "WordPress 6.4.2", "Moodle 4.1"
		if v := extractWordPressFromGenerator(gen); v != "" {
			comps = append(comps, scan.Component{
				Name:       "wordpress",
				Version:    v,
				Confidence: "confirmed",
				Evidence:   "html: meta generator=" + gen,
			})
		}
		if v := extractMoodleFromGenerator(gen); v != "" {
			comps = append(comps, scan.Component{
				Name:       "moodle",
				Version:    v,
				Confidence: "confirmed",
				Evidence:   "html: meta generator=" + gen,
			})
		}
	}

	if m := reJQuery.FindStringSubmatch(htmlSnippet); len(m) == 2 {
		comps = append(comps, scan.Component{
			Name:       "jquery",
			Version:    m[1],
			Ecosystem:  "npm", // for OSV
			Confidence: "likely",
			Evidence:   "html: jquery file version hint=" + m[1],
		})
	}

	return dedupeComponents(comps)
}

func header(h map[string]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func normalizeServerName(v string) string {
	vl := strings.ToLower(v)
	switch {
	case strings.Contains(vl, "nginx"):
		return "nginx"
	case strings.Contains(vl, "apache"):
		return "apache"
	case strings.Contains(vl, "cloudflare"):
		return "cloudflare"
	default:
		// fallback: first token
		parts := strings.Fields(v)
		if len(parts) > 0 {
			return strings.ToLower(parts[0])
		}
		return strings.ToLower(vl)
	}
}

func normalizePoweredBy(v string) string {
	vl := strings.ToLower(v)
	switch {
	case strings.Contains(vl, "asp.net"):
		return "aspnet"
	case strings.Contains(vl, "php"):
		return "php"
	default:
		parts := strings.Fields(v)
		if len(parts) > 0 {
			return strings.ToLower(parts[0])
		}
		return strings.ToLower(vl)
	}
}

func extractLooseVersion(s string) string {
	// very loose: finds first x.y or x.y.z
	re := regexp.MustCompile(`(\d+\.\d+(\.\d+)?)`)
	m := re.FindStringSubmatch(s)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func guessCMSVersion(name, html string) string {
	switch strings.ToLower(name) {
	case "wordpress":
		m := reWordPressVer.FindStringSubmatch(html)
		if len(m) > 1 {
			return m[1]
		}
	case "moodle":
		m := reMoodleVer.FindStringSubmatch(html)
		if len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

func extractWordPressFromGenerator(gen string) string {
	m := reWordPressVer.FindStringSubmatch(gen)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func extractMoodleFromGenerator(gen string) string {
	m := reMoodleVer.FindStringSubmatch(gen)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func confidenceFromPct(p int) string {
	switch {
	case p >= 85:
		return "confirmed"
	case p >= 60:
		return "likely"
	default:
		return "possible"
	}
}

func dedupeComponents(in []scan.Component) []scan.Component {
	type key struct{ n, v, e string }
	seen := map[key]bool{}
	var out []scan.Component
	for _, c := range in {
		k := key{n: strings.ToLower(c.Name), v: c.Version, e: c.Ecosystem}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + (i % 10))
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
