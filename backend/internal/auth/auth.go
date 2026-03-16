package auth

import (
	"net/http"
	"strings"
	"time"

	"dua/internal/scan"

	"golang.org/x/net/html"
)

var csrfNames = []string{"csrf", "_token", "csrfmiddlewaretoken", "__requestverificationtoken", "authenticity_token"}

func Analyze(targetURL string, headers map[string]string, htmlSnippet string, timeout time.Duration) scan.AuthResult {
	started := time.Now()
	out := scan.AuthResult{
		LoginPages:     []scan.LoginPage{},
		SessionIssues:  []scan.SessionIssue{},
		IDORCandidates: []scan.IDORCandidate{},
	}

	forms := parseForms(htmlSnippet)
	for _, f := range forms {
		isLogin := false
		fields := []string{}
		hasPassword := false
		hasCSRF := false
		for _, in := range f.Inputs {
			if in.Name != "" {
				fields = append(fields, in.Name)
			}
			if strings.EqualFold(in.Type, "password") {
				hasPassword = true
				autocomplete := strings.ToLower(strings.TrimSpace(in.Placeholder)) // fallback if placeholder copied
				_ = autocomplete
			}
			if isCSRFLike(in.Name) || isCSRFLike(in.Value) {
				hasCSRF = true
			}
		}

		if hasPassword || strings.Contains(strings.ToLower(targetURL), "login") || strings.Contains(strings.ToLower(targetURL), "signin") {
			isLogin = true
		}
		if !isLogin {
			continue
		}

		out.LoginPages = append(out.LoginPages, scan.LoginPage{
			URL:         targetURL,
			FormAction:  f.Action,
			InputFields: fields,
			AuthType:    "form",
		})

		if hasPassword && !hasCSRF {
			out.SessionIssues = append(out.SessionIssues, scan.SessionIssue{
				Type:     "missing_csrf_token",
				Severity: "high",
				Cookie:   "",
				Evidence: "login-like form with password field and no recognizable CSRF token",
			})
		}

		if hasPassword && hasAutocompletePasswordEnabled(f.Inputs) {
			out.SessionIssues = append(out.SessionIssues, scan.SessionIssue{
				Type:     "password_autocomplete_enabled",
				Severity: "low",
				Cookie:   "",
				Evidence: "password field without strict autocomplete control detected",
			})
		}
	}

	setCookie := header(headers, "Set-Cookie")
	if setCookie != "" {
		cookieLower := strings.ToLower(setCookie)
		if !strings.Contains(cookieLower, "httponly") {
			out.SessionIssues = append(out.SessionIssues, scan.SessionIssue{
				Type:     "missing_httponly",
				Severity: "high",
				Cookie:   setCookie,
				Evidence: "session cookie lacks HttpOnly flag",
			})
		}
		if !strings.Contains(cookieLower, "secure") {
			out.SessionIssues = append(out.SessionIssues, scan.SessionIssue{
				Type:     "missing_secure",
				Severity: "high",
				Cookie:   setCookie,
				Evidence: "session cookie lacks Secure flag",
			})
		}
		if !strings.Contains(cookieLower, "samesite") {
			out.SessionIssues = append(out.SessionIssues, scan.SessionIssue{
				Type:     "missing_samesite",
				Severity: "medium",
				Cookie:   setCookie,
				Evidence: "session cookie lacks SameSite attribute",
			})
		}
	}

	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if rateLimitMissing(targetURL, timeout) {
		out.SessionIssues = append(out.SessionIssues, scan.SessionIssue{
			Type:     "rate_limit_not_detected",
			Severity: "medium",
			Cookie:   "",
			Evidence: "5 controlled requests did not trigger 429 or explicit rate-limit headers",
		})
	}

	out.ExecutionTimeMs = time.Since(started).Milliseconds()
	return out
}

type parsedForm struct {
	Action string
	Method string
	Inputs []scan.FormInputField
}

func parseForms(htmlSnippet string) []parsedForm {
	doc, err := html.Parse(strings.NewReader(htmlSnippet))
	if err != nil {
		return nil
	}

	var forms []parsedForm
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			f := parsedForm{Action: attr(n, "action"), Method: attr(n, "method"), Inputs: []scan.FormInputField{}}
			collectInputs(n, &f)
			forms = append(forms, f)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return forms
}

func collectInputs(formNode *html.Node, f *parsedForm) {
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "textarea") {
			f.Inputs = append(f.Inputs, scan.FormInputField{
				Name:        attr(n, "name"),
				Type:        defaultIfEmpty(attr(n, "type"), "text"),
				Value:       attr(n, "value"),
				Placeholder: attr(n, "autocomplete"),
			})
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(formNode)
}

func isCSRFLike(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	for _, n := range csrfNames {
		if strings.Contains(v, n) {
			return true
		}
	}
	return false
}

func hasAutocompletePasswordEnabled(inputs []scan.FormInputField) bool {
	for _, in := range inputs {
		if !strings.EqualFold(in.Type, "password") {
			continue
		}
		autocomplete := strings.ToLower(strings.TrimSpace(in.Placeholder))
		if autocomplete == "" || autocomplete == "on" || autocomplete == "current-password" {
			return true
		}
	}
	return false
}

func rateLimitMissing(targetURL string, timeout time.Duration) bool {
	client := &http.Client{Timeout: timeout}
	seen429 := false
	hasRateHeaders := false
	for i := 0; i < 5; i++ {
		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "DUA-Scanner/0.2 auth-check")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			seen429 = true
		}
		if resp.Header.Get("X-RateLimit-Limit") != "" || resp.Header.Get("Retry-After") != "" || resp.Header.Get("RateLimit-Limit") != "" {
			hasRateHeaders = true
		}
		resp.Body.Close()
		time.Sleep(200 * time.Millisecond)
	}
	return !seen429 && !hasRateHeaders
}

func header(h map[string]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func attr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

func defaultIfEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
