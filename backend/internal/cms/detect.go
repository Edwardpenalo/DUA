package cms

import (
	"strings"

	"dua/internal/scan"
)

func Detect(finalURL string, headers map[string]string, html string) []scan.CMSFinding {
	var out []scan.CMSFinding

	hl := strings.ToLower(html)

	// --- WordPress fingerprints ---
	{
		var ev []string
		conf := 0

		// HTML paths
		if strings.Contains(hl, "/wp-content/") {
			ev = append(ev, "html: contains /wp-content/")
			conf += 45
		}
		if strings.Contains(hl, "/wp-includes/") {
			ev = append(ev, "html: contains /wp-includes/")
			conf += 35
		}

		// generator tag
		if strings.Contains(hl, `name="generator"`) && strings.Contains(hl, "wordpress") {
			ev = append(ev, `html: meta generator mentions wordpress`)
			conf += 40
		}

		// common endpoints referenced
		if strings.Contains(hl, "wp-emoji-release.min.js") {
			ev = append(ev, "html: wp-emoji-release.min.js")
			conf += 20
		}

		// cookies
		if v, ok := headers["Set-Cookie"]; ok {
			cl := strings.ToLower(v)
			if strings.Contains(cl, "wordpress_logged_in") {
				ev = append(ev, "cookie: wordpress_logged_in")
				conf += 50
			}
			if strings.Contains(cl, "wp-settings-") {
				ev = append(ev, "cookie: wp-settings-*")
				conf += 25
			}
		}

		if conf >= 60 {
			if conf > 100 {
				conf = 100
			}
			out = append(out, scan.CMSFinding{
				Name:       "wordpress",
				Confidence: conf,
				Evidence:   ev,
			})
		}
	}

	// --- Moodle fingerprints ---
	{
		var ev []string
		conf := 0

		// common moodle paths / patterns
		if strings.Contains(hl, "/login/index.php") {
			ev = append(ev, "html: contains /login/index.php")
			conf += 40
		}
		if strings.Contains(hl, "/course/") {
			ev = append(ev, "html: contains /course/")
			conf += 20
		}
		if strings.Contains(hl, "/theme/") {
			ev = append(ev, "html: contains /theme/")
			conf += 15
		}
		if strings.Contains(hl, "moodle") && strings.Contains(hl, "login") {
			ev = append(ev, "html: contains moodle + login")
			conf += 15
		}

		// cookies
		if v, ok := headers["Set-Cookie"]; ok {
			cl := strings.ToLower(v)
			if strings.Contains(cl, "moodlesession") {
				ev = append(ev, "cookie: MoodleSession")
				conf += 55
			}
		}

		// sometimes finalURL hints
		if strings.Contains(strings.ToLower(finalURL), "/login/index.php") {
			ev = append(ev, "url: final_url contains /login/index.php")
			conf += 20
		}

		if conf >= 60 {
			if conf > 100 {
				conf = 100
			}
			out = append(out, scan.CMSFinding{
				Name:       "moodle",
				Confidence: conf,
				Evidence:   ev,
			})
		}
	}

	return out
}
