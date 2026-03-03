export type ModuleId =
  | "http"
  | "dns"
  | "ports"
  | "tlsinfo"
  | "headers"
  | "tech"
  | "cms"
  | "dirs"
  | "vuln"
  | "risk";

export interface ScanRequest {
  target: string;
  modules: ModuleId[];
  options: {
    timeout_seconds: number;
    max_redirects: number;
    port_start: number;
    port_end: number;
    port_timeout_ms: number;
    port_concurrency: number;
  };
}

export interface ModuleError {
  module: string;
  message: string;
}

export interface ScanResult {
  target: string;
  modules: string[];
  started_at: string;
  finished_at: string;
  http?: {
    url: string;
    status: number;
    title: string;
    headers: Record<string, string>;
    final_url: string;
  };
  tech?: Array<{
    name: string;
    version?: string;
    confidence: number;
    evidence: string;
  }>;
  cms?: Array<{
    name: string;
    confidence: number;
    evidence: string[];
    version?: string;
  }>;
  dirs?: Array<{
    url: string;
    status: number;
    kind: string;
    evidence: string;
  }>;
  ports?: Array<{
    port: number;
    status: string;
    service?: string;
    banner?: string;
    notes?: string;
  }>;
  tls?: Array<{
    port: number;
    server_name: string;
    subject_cn?: string;
    sans?: string[];
    issuer_cn?: string;
    not_before?: string;
    not_after?: string;
    days_remaining?: number;
    expired: boolean;
    tls_version?: string;
    cipher_suite?: string;
  }>;
  headers?: {
    score: number;
    findings: Array<{
      name: string;
      status: string;
      severity: string;
      evidence?: string;
    }>;
    recommendations?: string[];
  };
  dns?: {
    target: string;
    hostname?: string;
    ips?: string[];
    cname?: string[];
    mx?: Array<{ host: string; pref: number }>;
    ns?: string[];
    reverse_ptr?: Array<{ ip: string; ptr?: string[] }>;
  };
  vuln?: {
    components: Array<{
      name: string;
      version?: string;
      ecosystem?: string;
      confidence: string;
      evidence: string;
    }>;
    findings: Array<{
      id: string;
      component: string;
      version?: string;
      ecosystem?: string;
      severity?: string;
      summary?: string;
      confidence: string;
      evidence: string;
      recommendation: string;
    }>;
    notes?: string[];
  };
  risk?: {
    score: number;
    summary: string;
    findings: Array<{
      id: string;
      severity: string;
      title: string;
      impact: string;
      evidence?: string;
      recommendation: string;
    }>;
  };
  errors?: ModuleError[];
}
