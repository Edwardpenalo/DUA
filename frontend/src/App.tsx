import { useState } from "react";
import { scanTarget } from "./api";
import type { ScanRequest, ScanResult, ModuleId } from "./types";
import "./styles.css";

function App() {
  const [apiBaseUrl] = useState("http://localhost:8080");
  const [target, setTarget] = useState("");
  const [selectedModules, setSelectedModules] = useState<ModuleId[]>(["http"]); // ← Cambiado de string[] a ModuleId[]
  const [timeout, setTimeout] = useState(10);
  const [maxRedirects, setMaxRedirects] = useState(5);
  const [portStart, setPortStart] = useState(1);
  const [portEnd, setPortEnd] = useState(1024);
  const [portTimeoutMs, setPortTimeoutMs] = useState(800);
  const [portConcurrency, setPortConcurrency] = useState(300);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const saved = localStorage.getItem("theme");
    return saved === "light" || saved === "dark" ? saved : "dark";
  });

  const modules: { id: ModuleId; name: string; desc: string }[] = [ // ← Tipado explícito
    { id: "http", name: "HTTP Probe", desc: "status, título, headers y URL final" },
    { id: "dns", name: "DNS Intel", desc: "A/AAAA, CNAME, MX, NS, PTR" },
    { id: "ports", name: "Port Scan", desc: "puertos abiertos y servicio probable" },
    { id: "tlsinfo", name: "TLS Info", desc: "certificado, versión TLS y cifrado" },
    { id: "headers", name: "Security Headers", desc: "análisis y score de cabeceras" },
    { id: "tech", name: "Tech Fingerprint", desc: "detección de tecnologías" },
    { id: "cms", name: "CMS Detect", desc: "detección de CMS y versión" },
    { id: "dirs", name: "Directory Enum", desc: "rutas descubiertas / wordlist" },
    { id: "vuln", name: "Vulnerability Check", desc: "hallazgos por componentes detectados" },
    { id: "risk", name: "Risk Score", desc: "riesgo consolidado del objetivo" },
  ];

  const toggleModule = (moduleId: ModuleId) => { // ← Cambiado de string a ModuleId
    setSelectedModules((prev) =>
      prev.includes(moduleId) ? prev.filter((m) => m !== moduleId) : [...prev, moduleId]
    );
  };

  const toggleTheme = () => {
    const newTheme = theme === "dark" ? "light" : "dark";
    setTheme(newTheme);
    localStorage.setItem("theme", newTheme);
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
      options: {
        timeout_seconds: timeout,
        max_redirects: maxRedirects,
        port_start: portStart,
        port_end: portEnd,
        port_timeout_ms: portTimeoutMs,
        port_concurrency: portConcurrency,
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

  return (
    <div className={`app ${theme}`}>
      <header>
        <h1>DUA</h1>
        <p>Reconocimiento web modular</p>
        <button onClick={toggleTheme} className="theme-toggle">
          Tema: {theme === "dark" ? "Oscuro" : "Claro"}
        </button>
      </header>

      <main>
        <section className="config-section">
          <h2>Configuración de escaneo</h2>

          <div className="form-group">
            <label>API Base URL</label>
            <input type="text" value={apiBaseUrl} disabled />
          </div>

          <div className="form-group">
            <label>Target</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://ejemplo.com"
              disabled={loading}
            />
          </div>

          <div className="modules-grid">
            <label>Módulos</label>
            {modules.map((mod) => (
              <div key={mod.id} className="module-card">
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
            <>
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
            </>
          )}

          <button onClick={handleScan} disabled={loading} className="btn-primary">
            {loading ? "Escaneando..." : "Ejecutar escaneo"}
          </button>
        </section>

        {error && (
          <div className="error-box">
            <strong>Error:</strong> {error}
          </div>
        )}

        {result && (
          <section className="results-section">
            <h2>Resultados</h2>
            <pre>{JSON.stringify(result, null, 2)}</pre>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
