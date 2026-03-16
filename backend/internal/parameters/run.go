package parameters

import (
	"net/url"
	"strings"
	"time"

	"dua/internal/scan"

	"golang.org/x/net/html"
)

var redirectParamHints = map[string]bool{
	"redirect":     true,
	"redirect_uri": true,
	"return":       true,
	"returnto":     true,
	"next":         true,
	"continue":     true,
	"url":          true,
	"dest":         true,
	"destination":  true,
}

func Run(pageURL, htmlSnippet string, opts scan.Options) scan.ParameterResult {
	started := time.Now()
	result := scan.ParameterResult{
		Endpoints:            []scan.Endpoint{},
		Parameters:           []scan.ParameterInfo{},
		ReflectionCandidates: []scan.ReflectionFinding{},
		OpenRedirectHints:    []scan.RedirectHint{},
	}

	paramIndex := map[string]*scan.ParameterInfo{}
	addParam := func(name, source, location, pType string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		p, ok := paramIndex[name]
		if !ok {
			created := &scan.ParameterInfo{Name: name}
			paramIndex[name] = created
			p = created
		}
		if !contains(p.Sources, source) {
			p.Sources = append(p.Sources, source)
		}
		if location != "" && !contains(p.Locations, location) {
			p.Locations = append(p.Locations, location)
		}
		if p.Type == "" && pType != "" {
			p.Type = pType
		}
	}

	u, err := url.Parse(pageURL)
	if err == nil {
		endpoint := scan.Endpoint{URL: pageURL, Method: "GET", Parameters: []string{}}
		for key, vals := range u.Query() {
			endpoint.Parameters = append(endpoint.Parameters, key)
			addParam(key, "query", pageURL, "string")
			if opts.ParamTestReflection {
				for _, v := range vals {
					if v != "" && strings.Contains(htmlSnippet, v) {
						result.ReflectionCandidates = append(result.ReflectionCandidates, scan.ReflectionFinding{
							URL:            pageURL,
							Parameter:      key,
							ReflectionType: "html",
							Confidence:     "medium",
							Payload:        v,
							Evidence:       "query value appears in HTML response",
						})
						break
					}
				}
			}
			if opts.ParamTestOpenRedirect && redirectParamHints[strings.ToLower(key)] {
				result.OpenRedirectHints = append(result.OpenRedirectHints, scan.RedirectHint{
					URL:        pageURL,
					Parameter:  key,
					Evidence:   "parameter name commonly used for redirects",
					Confidence: "medium",
				})
			}
		}
		result.Endpoints = append(result.Endpoints, endpoint)
	}

	forms := parseForms(htmlSnippet, pageURL)
	for _, f := range forms {
		endpoint := scan.Endpoint{
			URL:        f.Action,
			Method:     strings.ToUpper(f.Method),
			Form:       &f,
			Parameters: []string{},
		}

		for _, in := range f.Inputs {
			if in.Name == "" {
				continue
			}
			endpoint.Parameters = append(endpoint.Parameters, in.Name)
			addParam(in.Name, "form", f.Action, in.Type)
			if opts.ParamTestOpenRedirect && redirectParamHints[strings.ToLower(in.Name)] {
				result.OpenRedirectHints = append(result.OpenRedirectHints, scan.RedirectHint{
					URL:        f.Action,
					Parameter:  in.Name,
					Evidence:   "form field name commonly used for redirects",
					Confidence: "medium",
				})
			}
		}
		result.Endpoints = append(result.Endpoints, endpoint)
	}

	for _, p := range paramIndex {
		result.Parameters = append(result.Parameters, *p)
	}

	result.ExecutionTimeMs = time.Since(started).Milliseconds()
	return result
}

func parseForms(htmlSnippet, baseURL string) []scan.FormInfo {
	doc, err := html.Parse(strings.NewReader(htmlSnippet))
	if err != nil {
		return nil
	}

	var forms []scan.FormInfo
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			form := scan.FormInfo{
				Action: resolveAction(baseURL, attr(n, "action")),
				Method: strings.ToLower(defaultIfEmpty(attr(n, "method"), "get")),
				Inputs: []scan.FormInputField{},
			}
			collectInputs(n, &form)
			forms = append(forms, form)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return forms
}

func collectInputs(formNode *html.Node, f *scan.FormInfo) {
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "textarea" || n.Data == "select") {
			inputType := strings.ToLower(attr(n, "type"))
			if inputType == "" {
				if n.Data == "textarea" {
					inputType = "textarea"
				} else if n.Data == "select" {
					inputType = "select"
				} else {
					inputType = "text"
				}
			}
			f.Inputs = append(f.Inputs, scan.FormInputField{
				Name:        attr(n, "name"),
				Type:        inputType,
				Value:       attr(n, "value"),
				Placeholder: attr(n, "placeholder"),
			})
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(formNode)
}

func resolveAction(baseURL, action string) string {
	action = strings.TrimSpace(action)
	if action == "" {
		return baseURL
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return action
	}
	act, err := url.Parse(action)
	if err != nil {
		return action
	}
	return base.ResolveReference(act).String()
}

func attr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

func contains(in []string, value string) bool {
	for _, v := range in {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}

func defaultIfEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
