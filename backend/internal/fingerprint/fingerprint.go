package fingerprint

import (
	"fmt"
	"regexp"
	"strings"

	"dua/internal/scan"
)

func FromHTTP(headers map[string][]string, htmlBody string) []scan.TechFinding {
	var findings []scan.TechFinding
	detected := make(map[string]bool)

	// Check headers
	for key, values := range headers {
		headerStr := strings.ToLower(strings.Join(values, " "))

		// PHP
		if strings.Contains(headerStr, "php") && !detected["PHP"] {
			version := extractVersion(strings.Join(values, " "), `PHP/([\d.]+)`)
			findings = append(findings, scan.TechFinding{
				Name:       "PHP",
				Version:    version,
				Confidence: 95,
				Evidence:   fmt.Sprintf("%s: %s", key, strings.Join(values, " ")),
			})
			detected["PHP"] = true
		}

		// Apache
		if strings.Contains(headerStr, "apache") && !detected["Apache"] {
			version := extractVersion(strings.Join(values, " "), `Apache/([\d.]+)`)
			findings = append(findings, scan.TechFinding{
				Name:       "Apache",
				Version:    version,
				Confidence: 90,
				Evidence:   "Server header",
			})
			detected["Apache"] = true
		}

		// Nginx
		if strings.Contains(headerStr, "nginx") && !detected["Nginx"] {
			version := extractVersion(strings.Join(values, " "), `nginx/([\d.]+)`)
			findings = append(findings, scan.TechFinding{
				Name:       "Nginx",
				Version:    version,
				Confidence: 90,
				Evidence:   "Server header",
			})
			detected["Nginx"] = true
		}

		// IIS
		if strings.Contains(headerStr, "microsoft-iis") && !detected["IIS"] {
			version := extractVersion(strings.Join(values, " "), `Microsoft-IIS/([\d.]+)`)
			findings = append(findings, scan.TechFinding{
				Name:       "Microsoft IIS",
				Version:    version,
				Confidence: 90,
				Evidence:   "Server header",
			})
			detected["IIS"] = true
		}

		// ASP.NET
		if strings.Contains(headerStr, "asp.net") && !detected["ASP.NET"] {
			version := extractVersion(strings.Join(values, " "), `X-AspNet-Version: ([\d.]+)`)
			findings = append(findings, scan.TechFinding{
				Name:       "ASP.NET",
				Version:    version,
				Confidence: 85,
				Evidence:   "X-AspNet-Version header",
			})
			detected["ASP.NET"] = true
		}
	}

	// Check HTML for frameworks
	bodyLower := strings.ToLower(htmlBody)

	// React
	if (strings.Contains(bodyLower, "data-reactroot") || strings.Contains(bodyLower, "react")) && !detected["React"] {
		version := extractVersion(htmlBody, `react@([\d.]+)`)
		findings = append(findings, scan.TechFinding{
			Name:       "React",
			Version:    version,
			Confidence: 80,
			Evidence:   "HTML attributes and scripts",
		})
		detected["React"] = true
	}

	// Vue.js
	if strings.Contains(bodyLower, "vue") && !detected["Vue.js"] {
		version := extractVersion(htmlBody, `vue[.-]([\d.]+)`)
		findings = append(findings, scan.TechFinding{
			Name:       "Vue.js",
			Version:    version,
			Confidence: 80,
			Evidence:   "HTML scripts",
		})
		detected["Vue.js"] = true
	}

	// Angular
	if strings.Contains(bodyLower, "ng-version") && !detected["Angular"] {
		version := extractVersion(htmlBody, `ng-version="([^"]+)"`)
		findings = append(findings, scan.TechFinding{
			Name:       "Angular",
			Version:    version,
			Confidence: 90,
			Evidence:   "ng-version attribute",
		})
		detected["Angular"] = true
	}

	// jQuery
	if strings.Contains(bodyLower, "jquery") && !detected["jQuery"] {
		version := extractVersion(htmlBody, `jquery[.-]([\d.]+)`)
		findings = append(findings, scan.TechFinding{
			Name:       "jQuery",
			Version:    version,
			Confidence: 85,
			Evidence:   "HTML scripts",
		})
		detected["jQuery"] = true
	}

	// Cloudflare
	if len(headers["Cf-Ray"]) > 0 && !detected["Cloudflare"] {
		findings = append(findings, scan.TechFinding{
			Name:       "Cloudflare",
			Version:    "",
			Confidence: 95,
			Evidence:   "CF-Ray header",
		})
		detected["Cloudflare"] = true
	}

	// Meta generator tag
	metaFindings := analyzeMetaTags(htmlBody, detected)
	findings = append(findings, metaFindings...)

	return findings
}

func analyzeMetaTags(body string, detected map[string]bool) []scan.TechFinding {
	var findings []scan.TechFinding

	generatorRegex := regexp.MustCompile(`<meta[^>]*name=["']?generator["']?[^>]*content=["']([^"']+)["']`)
	if matches := generatorRegex.FindStringSubmatch(body); len(matches) > 1 {
		generator := matches[1]
		if !detected[generator] {
			parts := strings.Fields(generator)
			name := parts[0]
			version := ""

			if len(parts) > 1 {
				versionRegex := regexp.MustCompile(`([\d.]+)`)
				if vMatches := versionRegex.FindStringSubmatch(parts[1]); len(vMatches) > 0 {
					version = vMatches[1]
				}
			}

			findings = append(findings, scan.TechFinding{
				Name:       name,
				Version:    version,
				Confidence: 90,
				Evidence:   fmt.Sprintf("Meta generator: %s", generator),
			})
			detected[generator] = true
		}
	}

	return findings
}

func extractVersion(text string, pattern string) string {
	regex := regexp.MustCompile(pattern)
	matches := regex.FindStringSubmatch(text)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
