package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"dua/internal/cms"
	"dua/internal/direnum"
	"dua/internal/dnsintel"
	"dua/internal/fingerprint"
	"dua/internal/httpprobe"
	"dua/internal/portscan"
	"dua/internal/risk"
	"dua/internal/scan"
	"dua/internal/secheaders"
	"dua/internal/tlsinfo"
	"dua/internal/vuln"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/netintel/myip", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ip": clientIP(r),
		})
	})

	mux.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST only"})
			return
		}

		var req scan.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
			return
		}
		if strings.TrimSpace(req.Target) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "target is required"})
			return
		}

		// defaults
		if req.Options.TimeoutSeconds <= 0 {
			req.Options.TimeoutSeconds = 10
		}
		if req.Options.MaxRedirects <= 0 {
			req.Options.MaxRedirects = 5
		}

		start := time.Now().UTC()
		out := scan.Result{
			Target:     req.Target,
			Modules:    req.Modules,
			StartedAt:  start.Format(time.RFC3339),
			FinishedAt: "",
		}

		var htmlSnippet string

		for _, m := range req.Modules {
			normalizedModule := strings.ToLower(strings.TrimSpace(m))
			log.Printf("[DEBUG] ===== Iniciando módulo: %s =====", normalizedModule)
			moduleStart := time.Now()

			switch normalizedModule { // ← Normaliza el input

			case "http":
				res, err := httpprobe.Run(
					req.Target,
					time.Duration(req.Options.TimeoutSeconds)*time.Second,
					req.Options.MaxRedirects,
				)
				if err != nil {
					out.Errors = append(out.Errors, scan.ModuleError{Module: "http", Message: err.Error()})
					continue
				}

				htmlSnippet = res.BodySnippet

				out.HTTP = &scan.HTTPResult{
					URL:      res.URL,
					FinalURL: res.FinalURL,
					Status:   res.Status,
					Title:    res.Title,
					Headers:  res.Headers,
				}
			case "dns":
				rep := dnsintel.Resolve(req.Target)
				out.DNS = &rep
			case "dirs":
				if out.HTTP == nil {
					out.Errors = append(out.Errors, scan.ModuleError{Module: "dirs", Message: "run http module first"})
					continue
				}
				res, err := direnum.Run(
					out.HTTP.FinalURL,
					out.HTTP.Headers,
					htmlSnippet,
					direnum.Options{
						Timeout:         time.Duration(req.Options.TimeoutSeconds) * time.Second,
						Concurrency:     50,  // ← Aumenta de 25 a 50
						MaxPaths:        100, // ← Reduce de 300 a 100
						FollowRedirects: false,
					},
				)
				if err != nil {
					out.Errors = append(out.Errors, scan.ModuleError{Module: "dirs", Message: err.Error()})
					continue
				}
				out.Dirs = res
			case "risk":
				rep := risk.Evaluate(out)
				out.Risk = &rep
			case "tech":
				if out.HTTP == nil {
					out.Errors = append(out.Errors, scan.ModuleError{Module: "tech", Message: "run http module first"})
					continue
				}
				out.Tech = fingerprint.FromHTTP(out.HTTP.Headers, htmlSnippet)

			case "cms":
				if out.HTTP == nil {
					out.Errors = append(out.Errors, scan.ModuleError{Module: "cms", Message: "run http module first"})
					continue
				}
				out.CMS = cms.Detect(out.HTTP.FinalURL, out.HTTP.Headers, htmlSnippet)
			case "headers":
				if out.HTTP == nil {
					out.Errors = append(out.Errors, scan.ModuleError{Module: "headers", Message: "run http module first"})
					continue
				}
				rep := secheaders.Analyze(out.HTTP.Headers)
				out.Headers = &rep
			case "ports":
				log.Printf("[INFO] Iniciando módulo ports para target: %s", req.Target)

				host := req.Target
				host = strings.TrimPrefix(host, "http://")
				host = strings.TrimPrefix(host, "https://")
				host = strings.Split(host, "/")[0]

				if idx := strings.LastIndex(host, ":"); idx != -1 {
					host = host[:idx]
				}

				// defaults web-friendly
				if req.Options.PortStart <= 0 {
					req.Options.PortStart = 1
				}
				if req.Options.PortEnd <= 0 {
					req.Options.PortEnd = 1024
				}
				if req.Options.PortTimeoutMs <= 0 {
					req.Options.PortTimeoutMs = 500 // ← REDUCIDO de 800 a 500ms
				}
				if req.Options.PortConcurrency <= 0 {
					req.Options.PortConcurrency = 500 // ← AUMENTADO de 300 a 500
				}

				log.Printf("[INFO] Escaneando %s puertos %d-%d (timeout=%dms, concurrency=%d)",
					host, req.Options.PortStart, req.Options.PortEnd,
					req.Options.PortTimeoutMs, req.Options.PortConcurrency)

				startScan := time.Now()
				res, err := portscan.Run(host, portscan.Options{
					Start:       req.Options.PortStart,
					End:         req.Options.PortEnd,
					Timeout:     time.Duration(req.Options.PortTimeoutMs) * time.Millisecond,
					Concurrency: req.Options.PortConcurrency,
				})

				log.Printf("[INFO] Port scan completado en %v. Puertos encontrados: %d",
					time.Since(startScan), len(res))

				if err != nil {
					log.Printf("[ERROR] Port scan falló: %v", err)
					out.Errors = append(out.Errors, scan.ModuleError{Module: "ports", Message: err.Error()})
					continue
				}
				out.Ports = res
			case "vuln":
				// recomendado: correr después de http/tech/cms/headers
				rep := vuln.Run(out, htmlSnippet, vuln.Options{Timeout: 6 * time.Second})
				out.Vuln = &rep

			case "tlsinfo":
				host := req.Target
				host = strings.TrimPrefix(host, "http://")
				host = strings.TrimPrefix(host, "https://")
				host = strings.Split(host, "/")[0]

				timeout := 2 * time.Second
				if req.Options.PortTimeoutMs > 0 {
					timeout = time.Duration(req.Options.PortTimeoutMs) * time.Millisecond
				}

				portsToCheck := []int{}

				// prefer TLS ports found by ports module (if run earlier)
				if len(out.Ports) > 0 {
					for _, p := range out.Ports {
						if p.Status == "open" && p.Service == "tls" {
							portsToCheck = append(portsToCheck, p.Port)
						}
					}
				}

				// fallback
				if len(portsToCheck) == 0 {
					portsToCheck = append(portsToCheck, 443)
				}

				for _, p := range portsToCheck {
					f, err := tlsinfo.Inspect(host, p, tlsinfo.Options{Timeout: timeout})
					if err != nil {
						out.Errors = append(out.Errors, scan.ModuleError{
							Module:  "tlsinfo",
							Message: "port " + fmt.Sprintf("%d", p) + ": " + err.Error(),
						})
						continue
					}
					out.TLS = append(out.TLS, *f)
				}

			default:
				out.Errors = append(out.Errors, scan.ModuleError{Module: m, Message: "module not implemented yet"})
			}

			log.Printf("[DEBUG] ===== Módulo %s completado en %v =====", normalizedModule, time.Since(moduleStart))
		}

		out.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		writeJSON(w, http.StatusOK, out)
	})

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           withCORS(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Println("DUA API running on http://localhost:8080")
	log.Fatal(srv.ListenAndServe())
}

func clientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
