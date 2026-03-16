import { useState } from "react";
import { scanTarget } from "./api";
import type { ScanRequest, ScanResult, ModuleId, ScanMode } from "./types";
import "./styles.css";

function App() {
  const [target, setTarget] = useState("");
  const [selectedModules, setSelectedModules] = useState<ModuleId[]>(["http"]);
  const [scanMode, setScanMode] = useState<ScanMode>("audit");
  
  // General options
  const [timeout, setTimeout] = useState(60);
  const [maxRedirects, setMaxRedirects] = useState(5);
  
  // Port scan options
  const [portStart, setPortStart] = useState(1);
  const [portEnd, setPortEnd] = useState(1024);
  const [portTimeoutMs, setPortTimeoutMs] = useState(800);
  const [portConcurrency, setPortConcurrency] = useState(300);
  
  // Subdomain options
  const [subdomainPassiveOnly, setSubdomainPassiveOnly] = useState(false);
  const [subdomainActiveDNS, setSubdomainActiveDNS] = useState(true);
  const [subdomainResolve, setSubdomainResolve] = useState(true);
  const [subdomainProbeHTTP, setSubdomainProbeHTTP] = useState(true);
  
  // Parameter discovery options
  const [paramCrawlDepth, setParamCrawlDepth] = useState(2);
  const [paramTestReflection, setParamTestReflection] = useState(true);
  const [paramTestRedirect, setParamTestRedirect] = useState(true);
  const [paramMaxPages, setParamMaxPages] = useState(50);

  // Authorization flag for active modules
  const [iHaveAuthorization, setIHaveAuthorization] = useState(false);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const saved = localStorage.getItem("theme");
    return saved === "light" || saved === "dark" ? saved : "dark";
  });

  const modules: { id: ModuleId; name: string; desc: string; category: string }[] = [
    // Basic recon
    { id: "http", name: "HTTP Probe", desc: "Status, título, headers y URL final", category: "basic" },
    { id: "dns", name: "DNS Intel", desc: "A/AAAA, CNAME, MX, NS, PTR", category: "basic" },
    { id: "ports", name: "Port Scan", desc: "Puertos abiertos y servicio probable", category: "basic" },
    { id: "tlsinfo", name: "TLS Info", desc: "Certificado, versión TLS y cifrado", category: "basic" },
    
    // Web analysis
    { id: "headers", name: "Security Headers", desc: "Análisis y score de cabeceras", category: "web" },
    { id: "tech", name: "Tech Fingerprint", desc: "Detección de tecnologías", category: "web" },
    { id: "cms", name: "CMS Detect", desc: "Detección de CMS y versión", category: "web" },
    { id: "dirs", name: "Directory Enum", desc: "Rutas descubiertas / wordlist", category: "web" },
    
    // Advanced security (new modules)
    { id: "subdomains", name: "Subdomain Enum", desc: "CT logs + DNS brute + HTTP probe", category: "advanced" },
    { id: "parameters", name: "Parameter Discovery", desc: "Crawl + reflection + redirect hints", category: "advanced" },
    { id: "auth", name: "Auth Analysis", desc: "Login pages + session issues + IDOR", category: "advanced" },
    { id: "api", name: "API Discovery", desc: "Swagger/OpenAPI + GraphQL endpoints", category: "advanced" },
    { id: "cors", name: "CORS Analyzer", desc: "Origin reflection + misconfigurations", category: "advanced" },
    { id: "injections", name: "Injection Signals", desc: "XSS/SQLi markers (safe detection)", category: "advanced" },
    
    // Risk assessment
    { id: "vuln", name: "Vulnerability Check", desc: "Hallazgos por componentes detectados", category: "risk" },
    { id: "risk", name: "Risk Score", desc: "Riesgo consolidado del objetivo", category: "risk" },
  ];

  const toggleModule = (moduleId: ModuleId) => {
    setSelectedModules((prev) =>
      prev.includes(moduleId) ? prev.filter((m) => m !== moduleId) : [...prev, moduleId]
    );
  };

  const toggleTheme = () => {
    const newTheme = theme === "dark" ? "light" : "dark";
    setTheme(newTheme);
    localStorage.setItem("theme", newTheme);
  };

  const selectAllInCategory = (category: string) => {
    const categoryModules = modules.filter(m => m.category === category).map(m => m.id);
    setSelectedModules(prev => {
      const otherModules = prev.filter(id => !categoryModules.includes(id));
      return [...otherModules, ...categoryModules];
    });
  };

  const handleScan = async () => {
    if (!target.trim()) {
      setError("Ingresa un target válido");
      return;
    }

    if (selectedModules.length === 0) {
      setError("Selecciona al menos un módulo");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    const payload: ScanRequest = {
      target: target.trim(),
      modules: selectedModules,
      mode: scanMode,
      i_have_authorization: iHaveAuthorization,
      options: {
        timeout_seconds: timeout,
        max_redirects: maxRedirects,
        port_start: portStart,
        port_end: portEnd,
        port_timeout_ms: portTimeoutMs,
        port_concurrency: portConcurrency,
        subdomain_passive_only: subdomainPassiveOnly,
        subdomain_active_dns_brute: subdomainActiveDNS,
        subdomain_resolve: subdomainResolve,
        subdomain_probe_http: subdomainProbeHTTP,
        param_crawl_depth: paramCrawlDepth,
        param_test_reflection: paramTestReflection,
        param_test_open_redirect: paramTestRedirect,
        param_max_pages: paramMaxPages,
      },
    };

    try {
      const data = await scanTarget(payload);
      setResult(data);
    } catch (err: any) {
      setError(err.message || "Error desconocido");
    } finally {
      setLoading(false);
    }
  };

  const categoryGroups = {
    basic: modules.filter(m => m.category === "basic"),
    web: modules.filter(m => m.category === "web"),
    advanced: modules.filter(m => m.category === "advanced"),
    risk: modules.filter(m => m.category === "risk"),
  };

  return (
    <div className={`app ${theme}`}>
      <header>
        <h1> DUA</h1>
        <p>Advanced Security Audit & Bug Bounty Recon Tool</p>
        <button onClick={toggleTheme} className="theme-toggle">
          {theme === "dark" ? "Modo Oscuro" : "Modo Claro"}
        </button>
      </header>

      <main>
        <section className="config-section">
          <h2> Configuración de Escaneo</h2>
          <div className="form-group">
            <label>Target</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://ejemplo.com o ejemplo.com"
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label>Modo de Escaneo</label>
            <div className="scan-mode-toggle">
              <button
                className={scanMode === "audit" ? "active" : ""}
                onClick={() => setScanMode("audit")}
                disabled={loading}
              >
                 Audit (Seguro)
              </button>
              <button
                className={scanMode === "bug_bounty" ? "active" : ""}
                onClick={() => setScanMode("bug_bounty")}
                disabled={loading}
              >
                 Bug Bounty (Ofensivo)
              </button>
            </div>
            <small>
              {scanMode === "audit" 
                ? "Modo defensivo: análisis no intrusivo y seguro" 
                : "Modo ofensivo: recon activo controlado para bug bounty"}
            </small>
          </div>

          <div className="modules-section">
            <h3>Módulos de Escaneo</h3>
            
            {Object.entries(categoryGroups).map(([category, mods]) => (
              <div key={category} className="module-category">
                <div className="category-header">
                  <h4>
                    {category === "basic" && " Reconocimiento Básico"}
                    {category === "web" && "Análisis Web"}
                    {category === "advanced" && " Seguridad Avanzada"}
                    {category === "risk" && " Evaluación de Riesgo"}
                  </h4>
                  <button 
                    className="select-all-btn"
                    onClick={() => selectAllInCategory(category)}
                    disabled={loading}
                  >
                    Seleccionar todos
                  </button>
                </div>
                <div className="modules-grid">
                  {mods.map((mod) => (
                    <div
                      key={mod.id}
                      className={`module-card ${selectedModules.includes(mod.id) ? "selected" : ""}`}
                      onClick={() => !loading && toggleModule(mod.id)}
                    >
                      <label>
                        <input
                          type="checkbox"
                          checked={selectedModules.includes(mod.id)}
                          onChange={() => toggleModule(mod.id)}
                          disabled={loading}
                        />
                        <div>
                          <strong>{mod.name}</strong>
                          <small>{mod.desc}</small>
                        </div>
                      </label>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div className="advanced-options">
            <h3>Opciones Avanzadas</h3>
            
            <div className="form-row">
              <div className="form-group">
                <label>Timeout (s)</label>
                <input
                  type="number"
                  value={timeout}
                  onChange={(e) => setTimeout(Number(e.target.value))}
                  disabled={loading}
                />
              </div>
              <div className="form-group">
                <label>Max Redirects</label>
                <input
                  type="number"
                  value={maxRedirects}
                  onChange={(e) => setMaxRedirects(Number(e.target.value))}
                  disabled={loading}
                />
              </div>
            </div>

            {selectedModules.includes("ports") && (
              <details>
                <summary>Opciones de Port Scan</summary>
                <div className="form-row">
                  <div className="form-group">
                    <label>Port Start</label>
                    <input
                      type="number"
                      value={portStart}
                      onChange={(e) => setPortStart(Number(e.target.value))}
                      disabled={loading}
                    />
                  </div>
                  <div className="form-group">
                    <label>Port End</label>
                    <input
                      type="number"
                      value={portEnd}
                      onChange={(e) => setPortEnd(Number(e.target.value))}
                      disabled={loading}
                    />
                  </div>
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label>Port Timeout (ms)</label>
                    <input
                      type="number"
                      value={portTimeoutMs}
                      onChange={(e) => setPortTimeoutMs(Number(e.target.value))}
                      disabled={loading}
                    />
                  </div>
                  <div className="form-group">
                    <label>Port Concurrency</label>
                    <input
                      type="number"
                      value={portConcurrency}
                      onChange={(e) => setPortConcurrency(Number(e.target.value))}
                      disabled={loading}
                    />
                  </div>
                </div>
              </details>
            )}

            {selectedModules.includes("subdomains") && (
              <details>
                <summary>Opciones de Subdomain Enumeration</summary>
                <div className="checkbox-group">
                  <label>
                    <input
                      type="checkbox"
                      checked={subdomainPassiveOnly}
                      onChange={(e) => setSubdomainPassiveOnly(e.target.checked)}
                      disabled={loading}
                    />
                    Solo fuentes pasivas (CT logs, DNS NS)
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={subdomainActiveDNS}
                      onChange={(e) => setSubdomainActiveDNS(e.target.checked)}
                      disabled={loading || subdomainPassiveOnly}
                    />
                    DNS Bruteforce activo
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={subdomainResolve}
                      onChange={(e) => setSubdomainResolve(e.target.checked)}
                      disabled={loading}
                    />
                    Resolver subdominios (A/AAAA)
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={subdomainProbeHTTP}
                      onChange={(e) => setSubdomainProbeHTTP(e.target.checked)}
                      disabled={loading}
                    />
                    Probar HTTP/HTTPS en subdominios
                  </label>
                </div>
              </details>
            )}

            {selectedModules.includes("parameters") && (
              <details>
                <summary>Opciones de Parameter Discovery</summary>
                <div className="form-row">
                  <div className="form-group">
                    <label>Crawl Depth</label>
                    <input
                      type="number"
                      value={paramCrawlDepth}
                      onChange={(e) => setParamCrawlDepth(Number(e.target.value))}
                      disabled={loading}
                    />
                  </div>
                  <div className="form-group">
                    <label>Max Pages</label>
                    <input
                      type="number"
                      value={paramMaxPages}
                      onChange={(e) => setParamMaxPages(Number(e.target.value))}
                      disabled={loading}
                    />
                  </div>
                </div>
                <div className="checkbox-group">
                  <label>
                    <input
                      type="checkbox"
                      checked={paramTestReflection}
                      onChange={(e) => setParamTestReflection(e.target.checked)}
                      disabled={loading}
                    />
                    Test reflection (safe markers)
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={paramTestRedirect}
                      onChange={(e) => setParamTestRedirect(e.target.checked)}
                      disabled={loading}
                    />
                    Detect open redirect patterns
                  </label>
                </div>
              </details>
            )}
          </div>

          <button onClick={handleScan} disabled={loading} className="btn-primary">
            {loading ? "Escaneando..." : "Ejecutar Escaneo"}
          </button>

          {(selectedModules.includes("ports") || selectedModules.includes("dirs")) && (
            <div className="auth-consent">
              <label>
                <input
                  type="checkbox"
                  checked={iHaveAuthorization}
                  onChange={(e) => setIHaveAuthorization(e.target.checked)}
                  disabled={loading}
                />
                <span>
                  Confirmo que tengo autorización para escanear este objetivo activamente (requerido para <strong>ports</strong> / <strong>dirs</strong> en modo Bug Bounty)
                </span>
              </label>
            </div>
          )}
        </section>

        {error && (
          <div className="error-box">
            <strong>Error:</strong> {error}
          </div>
        )}

        {result && (
          <section className="results-section">
            <h2> Resultados del Escaneo</h2>
            
            {/* Risk Summary */}
            {result.risk_summary && (
              <div className="risk-summary-card">
                <h3> Resumen de Riesgo</h3>
                <div className="risk-score">
                  <div className="score-circle" data-score={result.risk_summary.overall_score}>
                    <span className="score-value">{result.risk_summary.overall_score.toFixed(1)}</span>
                    <span className="score-label">/100</span>
                  </div>
                  <div className="findings-summary">
                    {result.risk_summary.critical_findings > 0 && (
                      <div className="finding-badge critical">
                        {result.risk_summary.critical_findings} Critical
                      </div>
                    )}
                    {result.risk_summary.high_findings > 0 && (
                      <div className="finding-badge high">
                         {result.risk_summary.high_findings} High
                      </div>
                    )}
                    {result.risk_summary.medium_findings > 0 && (
                      <div className="finding-badge medium">
                        {result.risk_summary.medium_findings} Medium
                      </div>
                    )}
                    {result.risk_summary.low_findings > 0 && (
                      <div className="finding-badge low">
                         {result.risk_summary.low_findings} Low
                      </div>
                    )}
                  </div>
                </div>
                {scanMode === "bug_bounty" && result.risk_summary.opportunities_list && (
                  <div className="opportunities">
                    <h4>Bug Bounty Opportunities</h4>
                    {result.risk_summary.opportunities_list.map((opp, idx) => (
                      <div key={idx} className={`opportunity-card ${opp.severity}`}>
                        <h5>{opp.title}</h5>
                        <p><strong>Severity:</strong> {opp.severity.toUpperCase()}</p>
                        <p>{opp.description}</p>
                        <p><strong>Location:</strong> {opp.location}</p>
                        {opp.proof && <code>{opp.proof}</code>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Subdomain Results */}
            {result.subdomains && (
              <div className="result-module">
                <h3>Subdominios Encontrados</h3>
                <p><strong>Total:</strong> {result.subdomains.total} | <strong>Live:</strong> {result.subdomains.live}</p>
                {(result.subdomains.wildcards ?? []).length > 0 && (
                  <div className="warning">Wildcard DNS detectado: {result.subdomains.wildcards!.join(", ")}</div>
                )}
                <div className="subdomain-list">
                  {(result.subdomains.subdomains ?? []).map((sub, idx) => (
                    <div key={idx} className={`subdomain-item ${sub.live ? "live" : "dead"}`}>
                      <div className="subdomain-name">
                        {sub.live ? "Activo" : "Inactivo"} - {sub.name}
                      </div>
                      {(sub.ipv4 ?? []).length > 0 && <div className="subdomain-ip">{sub.ipv4!.join(", ")}</div>}
                      {sub.title && <div className="subdomain-title">{sub.title}</div>}
                      <div className="subdomain-meta">
                        <span>Fuente: {sub.source}</span>
                        {sub.status_code && <span> · Status: {sub.status_code}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Parameter Results */}
            {result.parameters && (
              <div className="result-module">
                <h3>Parámetros Descubiertos</h3>
                <p><strong>Endpoints:</strong> {(result.parameters.endpoints ?? []).length} | <strong>Parámetros:</strong> {(result.parameters.parameters ?? []).length}</p>
                
                {(result.parameters.reflection_candidates ?? []).length > 0 && (
                  <div className="findings-section">
                    <h4>Reflection Candidates (Posible XSS)</h4>
                    {result.parameters.reflection_candidates!.map((ref, idx) => (
                      <div key={idx} className={`finding-card ${ref.confidence}`}>
                        <strong>{ref.url}</strong>
                        <p>Parámetro: <code>{ref.parameter}</code></p>
                        <p>Tipo: {ref.reflection_type} | Confianza: {ref.confidence}</p>
                        <p>{ref.evidence}</p>
                      </div>
                    ))}
                  </div>
                )}

                {(result.parameters.open_redirect_hints ?? []).length > 0 && (
                  <div className="findings-section">
                    <h4>Open Redirect Hints</h4>
                    {result.parameters.open_redirect_hints!.map((hint, idx) => (
                      <div key={idx} className={`finding-card ${hint.confidence}`}>
                        <strong>{hint.url}</strong>
                        <p>Parámetro: <code>{hint.parameter}</code></p>
                        <p>{hint.evidence}</p>
                      </div>
                    ))}
                  </div>
                )}

                {(result.parameters.parameters ?? []).length > 0 && (
                  <details>
                    <summary>Ver todos los parámetros ({(result.parameters.parameters ?? []).length})</summary>
                    <table className="params-table">
                      <thead>
                        <tr><th>Nombre</th><th>Sources</th><th>Locations</th></tr>
                      </thead>
                      <tbody>
                        {result.parameters.parameters!.map((param, idx) => (
                          <tr key={idx}>
                            <td><code>{param.name}</code></td>
                            <td>{(param.sources ?? []).join(", ")}</td>
                            <td>{(param.locations ?? []).length} URLs</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </details>
                )}
              </div>
            )}

            {/* Tech Results */}
            {result.tech && result.tech.length > 0 && (
              <div className="result-module">
                <h3>Tecnologías Detectadas ({result.tech.length})</h3>
                <div className="tech-grid">
                  {result.tech.map((tech, idx) => (
                    <div key={idx} className="tech-card">
                      <div className="tech-header">
                        <strong>{tech.name}</strong>
                        {tech.version && (
                          <span className="tech-version">v{tech.version}</span>
                        )}
                      </div>
                      {tech.category && (
                        <div className="tech-category">{tech.category}</div>
                      )}
                      <div className="tech-confidence">
                        <div className="confidence-bar">
                          <div 
                            className="confidence-fill" 
                            style={{width: `${tech.confidence}%`}}
                          ></div>
                        </div>
                        <span>{tech.confidence}% confianza</span>
                      </div>
                      <div className="tech-evidence">
                        <small>{tech.evidence}</small>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* CMS Results */}
            {result.cms && result.cms.length > 0 && (
              <div className="result-module">
                <h3>CMS Detectados ({result.cms.length})</h3>
                <div className="cms-list">
                  {result.cms.map((cms, idx) => (
                    <div key={idx} className="cms-card">
                      <div className="cms-header">
                        <h4>{cms.name}</h4>
                        {cms.version && (
                          <span className="cms-version">
                             Version {cms.version}
                          </span>
                        )}
                      </div>
                      <div className="cms-meta">
                        <span className="cms-confidence">
                          ✓ Confianza: {cms.confidence}%
                        </span>
                      </div>
                      <div className="cms-evidence">
                        <strong>Evidencia encontrada:</strong>
                        <ul>
                          {cms.evidence.map((ev, i) => (
                            <li key={i}>{ev}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Auth Analysis */}
            {result.auth && (
              <div className="result-module">
                <h3>Auth Analysis</h3>

                {(result.auth.login_pages ?? []).length > 0 && (
                  <div className="findings-section">
                    <h4>Login Pages ({result.auth.login_pages!.length})</h4>
                    {result.auth.login_pages!.map((lp, idx) => (
                      <div key={idx} className="finding-card medium">
                        <strong>{lp.url}</strong>
                        <p>Form Action: <code>{lp.form_action}</code></p>
                        <p>Tipo: {lp.auth_type}</p>
                        <p>Campos: {(lp.input_fields ?? []).join(", ")}</p>
                      </div>
                    ))}
                  </div>
                )}

                {(result.auth.session_issues ?? []).length > 0 && (
                  <div className="findings-section">
                    <h4>Problemas de Sesión ({result.auth.session_issues!.length})</h4>
                    {result.auth.session_issues!.map((si, idx) => (
                      <div key={idx} className={`finding-card ${si.severity}`}>
                        <strong>{(si.type ?? "").split("_").join(" ").toUpperCase()}</strong>
                        <p>Severidad: <strong>{si.severity}</strong></p>
                        <p>{si.evidence}</p>
                        {si.cookie && <p><small>Cookie: <code>{si.cookie.substring(0, 120)}</code></small></p>}
                      </div>
                    ))}
                  </div>
                )}

                {(result.auth.session_issues ?? []).length === 0 && (result.auth.login_pages ?? []).length === 0 && (
                  <p style={{ opacity: 0.7 }}>No se detectaron páginas de login ni problemas de sesión.</p>
                )}
                <p><small>Tiempo: {result.auth.execution_time_ms}ms</small></p>
              </div>
            )}

            {/* CORS Results */}
            {result.cors && (result.cors.findings ?? []).length > 0 && (
              <div className="result-module">
                <h3>CORS Analysis</h3>
                {result.cors.findings!.map((f, idx) => (
                  <div key={idx} className={`finding-card ${f.severity === "critical" || f.severity === "high" ? "high" : f.severity === "medium" ? "medium" : "low"}`}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <strong>{f.url}</strong>
                      <span className={`badge sev-${f.severity}`}>{f.severity.toUpperCase()}</span>
                    </div>
                    {f.allow_origin && <p>Allow-Origin: <code>{f.allow_origin}</code></p>}
                    <p>Credentials: <strong>{f.allow_credentials ? "SI (riesgo)" : "No"}</strong></p>
                    <p>Explotable: {f.exploitable ? "SI" : "No"}</p>
                    <p>{f.exploitability_notes}</p>
                  </div>
                ))}
                <p><small>Tiempo: {result.cors.execution_time_ms}ms</small></p>
              </div>
            )}

            {/* API Discovery */}
            {result.api && ((result.api.swagger_endpoints ?? []).length > 0 || (result.api.graphql_endpoints ?? []).length > 0) && (
              <div className="result-module">
                <h3>API Discovery</h3>
                {(result.api.swagger_endpoints ?? []).length > 0 && (
                  <div className="findings-section">
                    <h4>Swagger / OpenAPI</h4>
                    {result.api.swagger_endpoints!.map((ep, idx) => (
                      <div key={idx} className="finding-card high">
                        <a href={ep} target="_blank" rel="noopener noreferrer">{ep}</a>
                      </div>
                    ))}
                  </div>
                )}
                {(result.api.graphql_endpoints ?? []).length > 0 && (
                  <div className="findings-section">
                    <h4>GraphQL</h4>
                    {result.api.graphql_endpoints!.map((ep, idx) => (
                      <div key={idx} className="finding-card medium">
                        <a href={ep} target="_blank" rel="noopener noreferrer">{ep}</a>
                      </div>
                    ))}
                  </div>
                )}
                <p><small>Tiempo: {result.api.execution_time_ms}ms</small></p>
              </div>
            )}

            {/* Injection Signals */}
            {result.injections && ((result.injections.xss_signals ?? []).length > 0 || (result.injections.sqli_signals ?? []).length > 0) && (
              <div className="result-module">
                <h3>Injection Signals</h3>
                {(result.injections.xss_signals ?? []).length > 0 && (
                  <div className="findings-section">
                    <h4>XSS Reflection Signals ({result.injections.xss_signals!.length})</h4>
                    {result.injections.xss_signals!.map((sig, idx) => (
                      <div key={idx} className="finding-card high">
                        <strong>{sig.url}</strong>
                        <p>Param: <code>{sig.parameter}</code> | Confianza: {sig.confidence}</p>
                        <p>{sig.evidence}</p>
                      </div>
                    ))}
                  </div>
                )}
                {(result.injections.sqli_signals ?? []).length > 0 && (
                  <div className="findings-section">
                    <h4>SQLi Pattern Signals ({result.injections.sqli_signals!.length})</h4>
                    {result.injections.sqli_signals!.map((sig, idx) => (
                      <div key={idx} className="finding-card medium">
                        <strong>{sig.url}</strong>
                        <p>Param: <code>{sig.parameter}</code> | Confianza: {sig.confidence}</p>
                        <p>{sig.evidence}</p>
                      </div>
                    ))}
                  </div>
                )}
                <p><small>Tiempo: {result.injections.execution_time_ms}ms</small></p>
              </div>
            )}

            {/* Raw JSON fallback */}
            <details className="raw-json">
              <summary>Ver JSON completo</summary>
              <pre>{JSON.stringify(result, null, 2)}</pre>
            </details>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
