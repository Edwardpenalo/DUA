package scan

import "context"

// ModuleRunner defines the interface all modules must implement
type ModuleRunner interface {
	// Run executes the module with context awareness
	Run(ctx context.Context, target string, opts ModuleOptions) (interface{}, error)

	// Name returns the module name
	Name() string
}

// SubdomainRunner interface for pluggable subdomain sources
type SubdomainSource interface {
	Enumerate(ctx context.Context, domain string) ([]string, error)
	Name() string // e.g., "crt.sh", "dns_ns", "custom_wordlist"
}
