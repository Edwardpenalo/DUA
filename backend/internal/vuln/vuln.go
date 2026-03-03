package vuln

import (
	"strings"
	"time"

	"dua/internal/scan"
	"dua/internal/vuln/providers"
)

type Options struct {
	Timeout time.Duration
}

func Run(out scan.Result, htmlSnippet string, opt Options) scan.VulnReport {
	if opt.Timeout <= 0 {
		opt.Timeout = 6 * time.Second
	}

	comps := DetectComponents(out, htmlSnippet)

	rep := scan.VulnReport{
		Components: comps,
	}

	// Query OSV only for components that have ecosystem + version
	for _, c := range comps {
		if c.Ecosystem == "" || c.Version == "" {
			continue
		}

		osv, err := providers.QueryOSV(c.Ecosystem, c.Name, c.Version, opt.Timeout)
		if err != nil {
			rep.Notes = append(rep.Notes, "osv query failed for "+c.Ecosystem+":"+c.Name+"@"+c.Version+": "+err.Error())
			continue
		}

		for _, v := range osv.Vulns {
			rep.Findings = append(rep.Findings, scan.VulnFinding{
				ID:             v.ID,
				Component:      c.Name,
				Version:        c.Version,
				Ecosystem:      c.Ecosystem,
				Severity:       pickSeverity(v.Severity),
				Summary:        v.Summary,
				Confidence:     c.Confidence,
				Evidence:       c.Evidence,
				Recommendation: "Validate the detected version and apply vendor updates/patches. If patching is not immediate, use compensating controls (WAF rules, strict allowlists, monitoring).",
			})
		}
	}

	// Notes for CMS without version (audit-friendly)
	for _, c := range comps {
		if (c.Name == "wordpress" || c.Name == "moodle") && c.Version == "" {
			rep.Notes = append(rep.Notes,
				"Detected "+strings.ToUpper(c.Name)+" but version is not confirmed from current evidence. Consider enabling non-intrusive version checks in a later iteration.",
			)
		}
	}

	return rep
}

func pickSeverity(sev []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) string {
	for _, s := range sev {
		if strings.EqualFold(s.Type, "CVSS_V3") || strings.EqualFold(s.Type, "CVSS_V2") {
			return s.Type + ":" + s.Score
		}
	}
	return ""
}
