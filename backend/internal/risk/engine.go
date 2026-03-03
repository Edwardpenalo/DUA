package risk

import (
	"sort"
	"strings"

	"dua/internal/scan"
)

func Evaluate(out scan.Result) scan.RiskReport {
	score := 100
	var findings []scan.RiskFinding

	add := func(id, sev, title, impact, evidence, rec string, penalty int) {
		findings = append(findings, scan.RiskFinding{
			ID:             id,
			Severity:       sev,
			Title:          title,
			Impact:         impact,
			Evidence:       evidence,
			Recommendation: rec,
		})
		score -= penalty
	}

	// ---------- WEB HARDENING (headers) ----------
	if out.Headers != nil {
		// Map findings by name for easy checks
		hf := map[string]scan.HeaderFinding{}
		for _, f := range out.Headers.Findings {
			hf[strings.ToLower(f.Name)] = f
		}

		// Missing CSP
		if f, ok := hf[strings.ToLower("Content-Security-Policy")]; ok && f.Status == "missing" {
			add(
				"WEB-HDR-001",
				"high",
				"Missing Content-Security-Policy (CSP)",
				"Increases exposure to XSS and content injection risks.",
				"CSP not present",
				"Define CSP starting with `default-src 'self'` and tighten with nonces/hashes where needed.",
				25,
			)
		}

		// Missing HSTS
		if f, ok := hf[strings.ToLower("Strict-Transport-Security")]; ok && f.Status == "missing" {
			add(
				"WEB-HDR-002",
				"high",
				"Missing Strict-Transport-Security (HSTS)",
				"Allows downgrade/SSL-stripping scenarios and weakens transport security posture.",
				"HSTS not present",
				"Enable HSTS on HTTPS: `Strict-Transport-Security: max-age=15552000; includeSubDomains; preload` (validate before preload).",
				20,
			)
		}

		// Clickjacking
		if f, ok := hf[strings.ToLower("X-Frame-Options")]; ok && f.Status == "missing" {
			add(
				"WEB-HDR-003",
				"medium",
				"Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
				"UI redressing/clickjacking becomes easier if the site can be framed by attackers.",
				"X-Frame-Options missing and CSP frame-ancestors not confirmed",
				"Set `X-Frame-Options: DENY` or `SAMEORIGIN`, or enforce `frame-ancestors` in CSP.",
				10,
			)
		}
	}

	// ---------- TLS (cert hygiene) ----------
	if len(out.TLS) > 0 {
		for _, t := range out.TLS {
			if t.Expired {
				add(
					"TLS-001",
					"critical",
					"Expired TLS certificate",
					"Clients may reject connections; increases MITM risk perception and compliance failures.",
					"Port "+itoa(t.Port)+", NotAfter="+t.NotAfter,
					"Renew the certificate and automate renewal (ACME/managed certs).",
					40,
				)
			} else if t.DaysRemaining > 0 && t.DaysRemaining <= 15 {
				add(
					"TLS-002",
					"medium",
					"TLS certificate near expiration",
					"Service disruption risk and compliance issues if it expires unexpectedly.",
					"Port "+itoa(t.Port)+", days_remaining="+itoa(t.DaysRemaining),
					"Renew/rotate certificate; implement monitoring/alerts for expiry thresholds.",
					10,
				)
			}

			if t.TLSVersion == "TLS1.0" || t.TLSVersion == "TLS1.1" {
				add(
					"TLS-003",
					"high",
					"Legacy TLS version negotiated",
					"Older TLS versions are weak and commonly disallowed by compliance baselines.",
					"Port "+itoa(t.Port)+", tls_version="+t.TLSVersion,
					"Disable TLS 1.0/1.1; enforce TLS 1.2+ (prefer TLS 1.3).",
					20,
				)
			}
		}
	}

	// ---------- Network exposure (ports) ----------
	if len(out.Ports) > 0 {
		for _, p := range out.Ports {
			if p.Status != "open" {
				continue
			}

			switch p.Port {
			case 23: // telnet
				add(
					"NET-001",
					"critical",
					"Telnet exposed",
					"Cleartext authentication and traffic; high risk of credential compromise.",
					"Open port 23",
					"Disable Telnet; migrate to SSH; restrict management interfaces via VPN/allowlist.",
					45,
				)
			case 21: // ftp
				add(
					"NET-002",
					"high",
					"FTP exposed",
					"Often cleartext credentials or weak configurations; increases attack surface.",
					"Open port 21",
					"Disable FTP or move to SFTP/FTPS; restrict by IP allowlist and enforce strong auth.",
					20,
				)
			case 3389: // rdp
				add(
					"NET-003",
					"high",
					"RDP exposed to network",
					"RDP exposure is frequently abused; increases brute-force and vulnerability risk.",
					"Open port 3389",
					"Restrict via VPN, enable MFA, NLA, account lockout, and monitor auth logs.",
					20,
				)
			case 445: // smb
				add(
					"NET-004",
					"high",
					"SMB exposed to network",
					"SMB exposure is high-risk, often targeted and can enable lateral movement scenarios.",
					"Open port 445",
					"Restrict SMB to internal networks; disable SMBv1; enforce signing; monitor access.",
					25,
				)
			}
		}
	}

	// ---------- CMS exposure (dirs + cms) ----------
	if len(out.CMS) > 0 {
		for _, c := range out.CMS {
			if c.Name == "wordpress" && c.Confidence >= 60 {
				// Check if wp-admin/wp-login discovered
				if hasPath(out.Dirs, "/wp-admin") || hasPath(out.Dirs, "/wp-login.php") {
					add(
						"CMS-001",
						"medium",
						"WordPress admin endpoints likely exposed",
						"Increases administrative attack surface (auth endpoints, enumeration, misconfig exposure).",
						"Detected WordPress + wp-admin/wp-login presence",
						"Restrict admin by IP/VPN, enforce MFA, rate-limit login, and harden WAF rules.",
						10,
					)
				}
			}
			if c.Name == "moodle" && c.Confidence >= 60 {
				if hasPath(out.Dirs, "/login/index.php") {
					add(
						"CMS-002",
						"medium",
						"Moodle login endpoint exposed",
						"Common target for credential stuffing; should be rate-limited and monitored.",
						"Detected Moodle + /login/index.php",
						"Enforce MFA where possible, rate limiting, lockout policy, and monitoring for auth anomalies.",
						8,
					)
				}
			}
		}
	}

	if score < 0 {
		score = 0
	}

	// Sort findings by severity then ID
	sort.Slice(findings, func(i, j int) bool {
		return sevRank(findings[i].Severity) > sevRank(findings[j].Severity)
	})

	summary := buildSummary(score, findings)

	return scan.RiskReport{
		Score:    score,
		Summary:  summary,
		Findings: findings,
	}
}

func hasPath(dirs []scan.DirFinding, needle string) bool {
	needle = strings.ToLower(needle)
	for _, d := range dirs {
		if strings.Contains(strings.ToLower(d.URL), needle) {
			return true
		}
	}
	return false
}

func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func buildSummary(score int, findings []scan.RiskFinding) string {
	if len(findings) == 0 {
		return "No material risks detected from enabled modules."
	}
	top := findings[0]
	return "Overall risk score " + itoa(score) + "/100. Top finding: " + top.Severity + " - " + top.Title + "."
}

func itoa(i int) string {
	// small helper to avoid fmt import
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
