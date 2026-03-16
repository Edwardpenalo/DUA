package scan

import (
	"context"
	"time"
)

// ScanMode defines the scanning profile
type ScanMode string

const (
	ModeAudit     ScanMode = "audit"      // non-intrusive, safe by default
	ModeBugBounty ScanMode = "bug_bounty" // more offensive recon, controlled
)

// ModuleOptions base for all module-specific options
type ModuleOptions interface{}

// ScanResult wraps all module results
type ScanResult struct {
	Target     string    `json:"target"`
	Mode       ScanMode  `json:"mode"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Duration   float64   `json:"duration_seconds"`

	// Module results (populated based on selected modules)
	Subdomains *SubdomainResult        `json:"subdomains,omitempty"`
	Parameters *ParameterResult        `json:"parameters,omitempty"`
	Auth       *AuthResult             `json:"auth,omitempty"`
	API        *APIResult              `json:"api,omitempty"`
	CORS       *CORSResult             `json:"cors,omitempty"`
	Injections *InjectionSignalsResult `json:"injections,omitempty"`

	// Consolidated risk
	RiskSummary *RiskSummary  `json:"risk_summary"`
	Errors      []ModuleError `json:"errors"`
}

// New module result types (to be defined in their respective packages)
type SubdomainResult struct {
	Subdomains      []SubdomainInfo `json:"subdomains"`
	Total           int             `json:"total"`
	Live            int             `json:"live"`
	Wildcards       []string        `json:"wildcards"`
	ExecutionTimeMs int64           `json:"execution_time_ms"`
}

type SubdomainInfo struct {
	Name         string   `json:"name"`
	IPv4         []string `json:"ipv4,omitempty"`
	IPv6         []string `json:"ipv6,omitempty"`
	CNAME        string   `json:"cname,omitempty"`
	Live         bool     `json:"live"`
	StatusCode   int      `json:"status_code,omitempty"`
	Title        string   `json:"title,omitempty"`
	ContentType  string   `json:"content_type,omitempty"`
	ServerHeader string   `json:"server_header,omitempty"`
	Source       string   `json:"source"`
	Fingerprint  string   `json:"fingerprint"`
}

type ParameterResult struct {
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
	Sources   []string `json:"sources"`
	Locations []string `json:"locations"`
	Type      string   `json:"type,omitempty"`
}

type ReflectionFinding struct {
	URL            string `json:"url"`
	Parameter      string `json:"parameter"`
	ReflectionType string `json:"reflection_type"`
	Confidence     string `json:"confidence"`
	Payload        string `json:"payload"`
	Evidence       string `json:"evidence"`
}

type RedirectHint struct {
	URL        string `json:"url"`
	Parameter  string `json:"parameter"`
	Evidence   string `json:"evidence"`
	Confidence string `json:"confidence"`
}

type AuthResult struct {
	LoginPages      []LoginPage     `json:"login_pages"`
	SessionIssues   []SessionIssue  `json:"session_issues"`
	IDORCandidates  []IDORCandidate `json:"idor_candidates"`
	ExecutionTimeMs int64           `json:"execution_time_ms"`
}

type LoginPage struct {
	URL         string   `json:"url"`
	FormAction  string   `json:"form_action"`
	InputFields []string `json:"input_fields"`
	AuthType    string   `json:"auth_type"` // "form", "basic", "digest", "oauth"
}

type SessionIssue struct {
	Type     string `json:"type"` // "missing_httponly", "missing_secure", "weak_scope"
	Severity string `json:"severity"`
	Cookie   string `json:"cookie"`
	Evidence string `json:"evidence"`
}

type IDORCandidate struct {
	URL        string  `json:"url"`
	Parameter  string  `json:"parameter"`
	IDType     string  `json:"id_type"` // "numeric", "uuid"
	Similarity float64 `json:"similarity"`
	Evidence   string  `json:"evidence"`
	Confidence string  `json:"confidence"`
}

type APIResult struct {
	SwaggerEndpoints []string      `json:"swagger_endpoints"`
	GraphQLEndpoints []string      `json:"graphql_endpoints"`
	APIEndpoints     []APIEndpoint `json:"api_endpoints"`
	ExecutionTimeMs  int64         `json:"execution_time_ms"`
}

type APIEndpoint struct {
	URL          string   `json:"url"`
	Method       string   `json:"method"`
	AuthRequired bool     `json:"auth_required"`
	Parameters   []string `json:"parameters"`
	Source       string   `json:"source"` // "swagger", "graphql", "discovery"
}

type CORSResult struct {
	Findings        []CORSFinding `json:"findings"`
	ExecutionTimeMs int64         `json:"execution_time_ms"`
}

type CORSFinding struct {
	URL                 string `json:"url"`
	AllowOrigin         string `json:"allow_origin"`
	AllowCredentials    bool   `json:"allow_credentials"`
	Exploitable         bool   `json:"exploitable"`
	Severity            string `json:"severity"`
	ExploitabilityNotes string `json:"exploitability_notes"`
}

type InjectionSignalsResult struct {
	SQLiSignals     []InjectionSignal `json:"sqli_signals"`
	XSSSignals      []InjectionSignal `json:"xss_signals"`
	ExecutionTimeMs int64             `json:"execution_time_ms"`
}

type InjectionSignal struct {
	URL        string `json:"url"`
	Parameter  string `json:"parameter"`
	Type       string `json:"type"` // "sqli", "xss", "time_based"
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence"`
	Payload    string `json:"payload"`
}

// ModuleError captures execution errors
type ModuleError struct {
	Module  string `json:"module"`
	Message string `json:"message"`
}

// RiskSummary consolidates findings across modules
type RiskSummary struct {
	OverallScore      float64                `json:"overall_score"` // 0-100
	CriticalFindings  int                    `json:"critical_findings"`
	HighFindings      int                    `json:"high_findings"`
	MediumFindings    int                    `json:"medium_findings"`
	LowFindings       int                    `json:"low_findings"`
	AuditSummary      string                 `json:"audit_summary"`
	BugBountySummary  string                 `json:"bug_bounty_summary"`
	OpportunitiesList []BugBountyOpportunity `json:"opportunities_list,omitempty"`
}

// BugBountyOpportunity is a actionable finding for bounty hunters
type BugBountyOpportunity struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"` // critical, high, medium, low
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Location    string `json:"location"`
	Proof       string `json:"proof,omitempty"`
}

// ContextWithTimeout helper
func ContextWithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

// Legacy types for backward compatibility
type Request struct {
	Target             string   `json:"target"`
	Modules            []string `json:"modules"`
	Mode               ScanMode `json:"mode,omitempty"`
	IHaveAuthorization bool     `json:"i_have_authorization,omitempty"`
	Options            Options  `json:"options"`
}

type Options struct {
	TimeoutSeconds  int `json:"timeout_seconds"`
	MaxRedirects    int `json:"max_redirects"`
	PortStart       int `json:"port_start"`
	PortEnd         int `json:"port_end"`
	PortTimeoutMs   int `json:"port_timeout_ms"`
	PortConcurrency int `json:"port_concurrency"`

	// Subdomain options
	SubdomainPassiveOnly    bool `json:"subdomain_passive_only"`
	SubdomainActiveDNSBrute bool `json:"subdomain_active_dns_brute"`
	SubdomainResolve        bool `json:"subdomain_resolve"`
	SubdomainProbeHTTP      bool `json:"subdomain_probe_http"`

	// Parameter discovery options
	ParamCrawlDepth       int  `json:"param_crawl_depth"`
	ParamTestReflection   bool `json:"param_test_reflection"`
	ParamTestOpenRedirect bool `json:"param_test_open_redirect"`
	ParamMaxPages         int  `json:"param_max_pages"`
}

type Result struct {
	Target          string                  `json:"target"`
	Modules         []string                `json:"modules"`
	Mode            ScanMode                `json:"mode,omitempty"`
	StartedAt       string                  `json:"started_at"`
	FinishedAt      string                  `json:"finished_at"`
	DurationSeconds float64                 `json:"duration_seconds,omitempty"`
	HTTP            *HTTPResult             `json:"http,omitempty"`
	Tech            []TechFinding           `json:"tech,omitempty"`
	CMS             []CMSFinding            `json:"cms,omitempty"`
	Errors          []ModuleError           `json:"errors,omitempty"`
	Dirs            []DirFinding            `json:"dirs,omitempty"`
	Ports           []PortFinding           `json:"ports,omitempty"`
	TLS             []TLSFinding            `json:"tls,omitempty"`
	Headers         *HeadersReport          `json:"headers,omitempty"`
	DNS             *DNSReport              `json:"dns,omitempty"`
	Vuln            *VulnReport             `json:"vuln,omitempty"`
	Risk            *RiskReport             `json:"risk,omitempty"`
	Subdomains      *SubdomainResult        `json:"subdomains,omitempty"`
	Parameters      *ParameterResult        `json:"parameters,omitempty"`
	Auth            *AuthResult             `json:"auth,omitempty"`
	API             *APIResult              `json:"api,omitempty"`
	CORS            *CORSResult             `json:"cors,omitempty"`
	Injections      *InjectionSignalsResult `json:"injections,omitempty"`
	RiskSummary     *RiskSummary            `json:"risk_summary,omitempty"`
}

type DirFinding struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Kind     string `json:"kind"`
	Evidence string `json:"evidence"`
}

type HTTPResult struct {
	URL      string            `json:"url"`
	Status   int               `json:"status"`
	Title    string            `json:"title"`
	Headers  map[string]string `json:"headers"`
	FinalURL string            `json:"final_url"`
}

type TechFinding struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Category   string `json:"category,omitempty"`
	Confidence int    `json:"confidence"`
	Evidence   string `json:"evidence"`
}

type CMSFinding struct {
	Name       string   `json:"name"`
	Confidence int      `json:"confidence"`
	Evidence   []string `json:"evidence"`
	Version    string   `json:"version,omitempty"`
}

type PortFinding struct {
	Port    int    `json:"port"`
	Status  string `json:"status"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
	Notes   string `json:"notes,omitempty"`
}

type TLSFinding struct {
	Port          int      `json:"port"`
	ServerName    string   `json:"server_name"`
	SubjectCN     string   `json:"subject_cn,omitempty"`
	SANs          []string `json:"sans,omitempty"`
	IssuerCN      string   `json:"issuer_cn,omitempty"`
	NotBefore     string   `json:"not_before,omitempty"`
	NotAfter      string   `json:"not_after,omitempty"`
	DaysRemaining int      `json:"days_remaining,omitempty"`
	Expired       bool     `json:"expired"`
	TLSVersion    string   `json:"tls_version,omitempty"`
	CipherSuite   string   `json:"cipher_suite,omitempty"`
}

type HeadersReport struct {
	Score           int             `json:"score"`
	Findings        []HeaderFinding `json:"findings"`
	Recommendations []string        `json:"recommendations,omitempty"`
}

type HeaderFinding struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence,omitempty"`
}

type DNSReport struct {
	Target     string        `json:"target"`
	Hostname   string        `json:"hostname,omitempty"`
	IPs        []string      `json:"ips,omitempty"`
	CNAME      []string      `json:"cname,omitempty"`
	MX         []DNSMXRecord `json:"mx,omitempty"`
	NS         []string      `json:"ns,omitempty"`
	ReversePTR []DNSPTR      `json:"reverse_ptr,omitempty"`
}

type DNSMXRecord struct {
	Host string `json:"host"`
	Pref uint16 `json:"pref"`
}

type DNSPTR struct {
	IP  string   `json:"ip"`
	PTR []string `json:"ptr,omitempty"`
}

type RiskReport struct {
	Score    int           `json:"score"`
	Summary  string        `json:"summary"`
	Findings []RiskFinding `json:"findings"`
}

type RiskFinding struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Impact         string `json:"impact"`
	Evidence       string `json:"evidence,omitempty"`
	Recommendation string `json:"recommendation"`
}

type VulnReport struct {
	Components []Component   `json:"components"`
	Findings   []VulnFinding `json:"findings"`
	Notes      []string      `json:"notes,omitempty"`
}

type Component struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Ecosystem  string `json:"ecosystem,omitempty"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence"`
}

type VulnFinding struct {
	ID             string `json:"id"`
	Component      string `json:"component"`
	Version        string `json:"version,omitempty"`
	Ecosystem      string `json:"ecosystem,omitempty"`
	Severity       string `json:"severity,omitempty"`
	Summary        string `json:"summary,omitempty"`
	Confidence     string `json:"confidence"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation"`
}
