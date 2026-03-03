package cms

import (
	"fmt"
	"regexp"
	"strings"

	"dua/internal/scan"
)

func FromHTTP(headers map[string][]string, body string) []scan.CMSFinding {
	var findings []scan.CMSFinding
	detected := make(map[string]bool)

	// Check meta generator
	generatorRegex := regexp.MustCompile(`<meta[^>]*name=["']?generator["']?[^>]*content=["']([^"']+)["']`)
	if matches := generatorRegex.FindStringSubmatch(body); len(matches) > 1 {
		generator := matches[1]
		name, version := parseGenerator(generator)
		if name != "" && !detected[name] {
			findings = append(findings, scan.CMSFinding{
				Name:       name,
				Version:    version,
				Confidence: 90,
				Evidence:   []string{fmt.Sprintf("Meta generator: %s", generator)},
			})
			detected[name] = true
		}
	}

	// WordPress
	if detectWordPress(body) && !detected["WordPress"] {
		version := extractWordPressVersion(body)
		findings = append(findings, scan.CMSFinding{
			Name:       "WordPress",
			Version:    version,
			Confidence: 85,
			Evidence:   []string{"wp-content paths", "wp-includes paths"},
		})
		detected["WordPress"] = true
	}

	// Joomla
	if detectJoomla(body) && !detected["Joomla"] {
		version := extractJoomlaVersion(body)
		findings = append(findings, scan.CMSFinding{
			Name:       "Joomla",
			Version:    version,
			Confidence: 80,
			Evidence:   []string{"Joomla components detected"},
		})
		detected["Joomla"] = true
	}

	// Drupal
	if detectDrupal(body) && !detected["Drupal"] {
		version := extractDrupalVersion(body)
		findings = append(findings, scan.CMSFinding{
			Name:       "Drupal",
			Version:    version,
			Confidence: 80,
			Evidence:   []string{"Drupal paths and scripts detected"},
		})
		detected["Drupal"] = true
	}

	// Moodle
	if detectMoodle(body) && !detected["Moodle"] {
		version := extractMoodleVersion(body)
		findings = append(findings, scan.CMSFinding{
			Name:       "Moodle",
			Version:    version,
			Confidence: 75,
			Evidence:   []string{"Moodle theme and scripts detected"},
		})
		detected["Moodle"] = true
	}

	return findings
}

func parseGenerator(generator string) (string, string) {
	parts := strings.Fields(generator)
	if len(parts) == 0 {
		return "", ""
	}

	name := parts[0]
	version := ""

	if len(parts) > 1 {
		versionRegex := regexp.MustCompile(`([\d.]+)`)
		if matches := versionRegex.FindStringSubmatch(parts[1]); len(matches) > 0 {
			version = matches[1]
		}
	}

	return name, version
}

func detectWordPress(body string) bool {
	return strings.Contains(body, "wp-content") || strings.Contains(body, "wp-includes")
}

func extractWordPressVersion(body string) string {
	regex := regexp.MustCompile(`<meta name="generator" content="WordPress ([\d.]+)`)
	if matches := regex.FindStringSubmatch(body); len(matches) > 1 {
		return matches[1]
	}

	regex = regexp.MustCompile(`wp-(?:content|includes)[^"]*\?ver=([\d.]+)`)
	if matches := regex.FindStringSubmatch(body); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func detectJoomla(body string) bool {
	return strings.Contains(body, "components/com_") || strings.Contains(body, "/modules/mod_")
}

func extractJoomlaVersion(body string) string {
	regex := regexp.MustCompile(`<meta name="generator" content="Joomla![^"]*Version ([\d.]+)`)
	if matches := regex.FindStringSubmatch(body); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func detectDrupal(body string) bool {
	bodyLower := strings.ToLower(body)
	return strings.Contains(bodyLower, "/sites/default/") || strings.Contains(bodyLower, "drupal")
}

func extractDrupalVersion(body string) string {
	regex := regexp.MustCompile(`<meta name="Generator" content="Drupal ([\d.]+)`)
	if matches := regex.FindStringSubmatch(body); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func detectMoodle(body string) bool {
	bodyLower := strings.ToLower(body)
	return strings.Contains(bodyLower, "/theme/moodle/") || strings.Contains(bodyLower, "moodle")
}

func extractMoodleVersion(body string) string {
	regex := regexp.MustCompile(`Moodle\s+([\d.]+)`)
	if matches := regex.FindStringSubmatch(body); len(matches) > 1 {
		return matches[1]
	}
	return ""
}
