package apidiscovery

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"dua/internal/scan"
)

func Run(baseURL string, timeout time.Duration) scan.APIResult {
	started := time.Now()
	out := scan.APIResult{
		SwaggerEndpoints: []string{},
		GraphQLEndpoints: []string{},
		APIEndpoints:     []scan.APIEndpoint{},
	}

	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	client := &http.Client{Timeout: timeout}
	candidates := []struct {
		path   string
		source string
	}{
		{path: "/swagger", source: "swagger"},
		{path: "/swagger/index.html", source: "swagger"},
		{path: "/openapi.json", source: "swagger"},
		{path: "/swagger.json", source: "swagger"},
		{path: "/api-docs", source: "swagger"},
		{path: "/graphql", source: "graphql"},
		{path: "/graphiql", source: "graphql"},
	}

	for _, c := range candidates {
		u := resolveURL(baseURL, c.path)
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "DUA-Scanner/0.2 api-discovery")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			continue
		}

		if c.source == "swagger" {
			out.SwaggerEndpoints = appendIfMissing(out.SwaggerEndpoints, u)
		} else {
			out.GraphQLEndpoints = appendIfMissing(out.GraphQLEndpoints, u)
		}

		out.APIEndpoints = append(out.APIEndpoints, scan.APIEndpoint{
			URL:          u,
			Method:       "GET",
			AuthRequired: resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden,
			Parameters:   []string{},
			Source:       c.source,
		})
	}

	out.ExecutionTimeMs = time.Since(started).Milliseconds()
	return out
}

func resolveURL(baseURL, path string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return strings.TrimSuffix(baseURL, "/") + path
	}
	ref, err := url.Parse(path)
	if err != nil {
		return strings.TrimSuffix(baseURL, "/") + path
	}
	return base.ResolveReference(ref).String()
}

func appendIfMissing(in []string, value string) []string {
	for _, v := range in {
		if v == value {
			return in
		}
	}
	return append(in, value)
}
