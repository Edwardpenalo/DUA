package scan

type Request struct {
	Target  string   `json:"target"`
	Modules []string `json:"modules"` // e.g. ["http","tech","cms"]
	Options Options  `json:"options"`
}

type Options struct {
	TimeoutSeconds  int `json:"timeout_seconds"` // default 10
	MaxRedirects    int `json:"max_redirects"`   // default 5
	PortStart       int `json:"port_start"`
	PortEnd         int `json:"port_end"`
	PortTimeoutMs   int `json:"port_timeout_ms"`
	PortConcurrency int `json:"port_concurrency"`
}

type Result struct {
	Target     string         `json:"target"`
	Modules    []string       `json:"modules"`
	StartedAt  string         `json:"started_at"`
	FinishedAt string         `json:"finished_at"`
	HTTP       *HTTPResult    `json:"http,omitempty"`
	Tech       []TechFinding  `json:"tech,omitempty"`
	CMS        []CMSFinding   `json:"cms,omitempty"`
	Errors     []ModuleError  `json:"errors,omitempty"`
	Dirs       []DirFinding   `json:"dirs,omitempty"`
	Ports      []PortFinding  `json:"ports,omitempty"`
	TLS        []TLSFinding   `json:"tls,omitempty"`
	Headers    *HeadersReport `json:"headers,omitempty"`
	DNS        *DNSReport     `json:"dns,omitempty"`
	Vuln       *VulnReport    `json:"vuln,omitempty"`
	Risk       *RiskReport    `json:"risk,omitempty"`
}
type DirFinding struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Kind     string `json:"kind"`     // "discovered" | "wordlist" | "robots" | "sitemap"
	Evidence string `json:"evidence"` // e.g. "href", "robots", "wordlist"
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
	Confidence int    `json:"confidence"` // 0-100
	Evidence   string `json:"evidence"`
}

type CMSFinding struct {
	Name       string   `json:"name"`       // wordpress, moodle, joomla...
	Confidence int      `json:"confidence"` // 0-100
	Evidence   []string `json:"evidence"`
	Version    string   `json:"version,omitempty"`
}

type ModuleError struct {
	Module  string `json:"module"`
	Message string `json:"message"`
}
type PortFinding struct {
	Port    int    `json:"port"`
	Status  string `json:"status"`            // open
	Service string `json:"service,omitempty"` // http, tls, ssh, unknown...
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
	Score           int             `json:"score"` // 0-100
	Findings        []HeaderFinding `json:"findings"`
	Recommendations []string        `json:"recommendations,omitempty"`
}

type HeaderFinding struct {
	Name     string `json:"name"`
	Status   string `json:"status"`   // present | missing | weak
	Severity string `json:"severity"` // info | low | medium | high
	Evidence string `json:"evidence,omitempty"`
}
type DNSReport struct {
	Target     string        `json:"target"`
	Hostname   string        `json:"hostname,omitempty"`
	IPs        []string      `json:"ips,omitempty"` // A + AAAA
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
	Score    int           `json:"score"` // 0-100
	Summary  string        `json:"summary"`
	Findings []RiskFinding `json:"findings"`
}

type RiskFinding struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"` // low | medium | high | critical
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
	Name       string `json:"name"` // e.g. "jquery", "aspnetcore"
	Version    string `json:"version,omitempty"`
	Ecosystem  string `json:"ecosystem,omitempty"` // osv ecosystem: npm, PyPI, NuGet, Go, Maven, Packagist...
	Confidence string `json:"confidence"`          // confirmed | likely | possible
	Evidence   string `json:"evidence"`            // where we got it
}

type VulnFinding struct {
	ID             string `json:"id"`        // e.g. OSV-2023-XXXX
	Component      string `json:"component"` // name
	Version        string `json:"version,omitempty"`
	Ecosystem      string `json:"ecosystem,omitempty"`
	Severity       string `json:"severity,omitempty"` // if provided
	Summary        string `json:"summary,omitempty"`
	Confidence     string `json:"confidence"` // confidence inherited from component
	Evidence       string `json:"evidence"`   // evidence inherited
	Recommendation string `json:"recommendation"`
}
