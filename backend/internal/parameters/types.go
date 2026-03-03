package parameters

type Result struct {
	Endpoints            []Endpoint          `json:"endpoints"`
	Parameters           []ParameterInfo     `json:"parameters"`
	ReflectionCandidates []ReflectionFinding `json:"reflection_candidates"`
	OpenRedirectHints    []RedirectHint      `json:"open_redirect_hints"`
	ExecutionTimeMs      int64               `json:"execution_time_ms"`
}

type Endpoint struct {
	URL         string    `json:"url"`
	Method      string    `json:"method"`
	Form        *FormInfo `json:"form,omitempty"`
	JSEndpoints []string  `json:"js_endpoints,omitempty"`
	Parameters  []string  `json:"parameters"`
}

type FormInfo struct {
	Action string           `json:"action"`
	Method string           `json:"method"`
	Inputs []FormInputField `json:"inputs"`
}

type FormInputField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Value       string `json:"value,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
}

type ParameterInfo struct {
	Name      string   `json:"name"`
	Sources   []string `json:"sources"`        // "query", "form", "js_endpoint", "header"
	Locations []string `json:"locations"`      // URLs where found
	Type      string   `json:"type,omitempty"` // from form analysis
}

type ReflectionFinding struct {
	URL            string `json:"url"`
	Parameter      string `json:"parameter"`
	ReflectionType string `json:"reflection_type"` // "html", "json", "url"
	Confidence     string `json:"confidence"`      // "high", "medium", "low"
	Payload        string `json:"payload"`
	Evidence       string `json:"evidence"`
}

type RedirectHint struct {
	URL        string `json:"url"`
	Parameter  string `json:"parameter"`
	Evidence   string `json:"evidence"`
	Confidence string `json:"confidence"`
}

type Options struct {
	Timeout           int      `json:"timeout_seconds"`
	CrawlDepth        int      `json:"crawl_depth"`
	TestReflection    bool     `json:"test_reflection"`
	TestOpenRedirect  bool     `json:"test_open_redirect"`
	CustomPayloads    []string `json:"custom_payloads"` // optional
	MaxPages          int      `json:"max_pages"`
	IncludeJSAnalysis bool     `json:"include_js_analysis"`
}
