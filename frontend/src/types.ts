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
  | "risk"
  | "subdomains"
  | "parameters"
  | "auth"
  | "api"
  | "cors"
  | "injections";

export type ScanMode = "audit" | "bug_bounty";

export interface ScanRequest {
  target: string;
  modules: ModuleId[];
  mode?: ScanMode;
  i_have_authorization?: boolean;
  options: ScanOptions;
}

export interface ScanOptions {
  timeout_seconds: number;
  max_redirects: number;
  port_start: number;
  port_end: number;
  port_timeout_ms: number;
  port_concurrency: number;
  
  // Subdomain options
  subdomain_passive_only?: boolean;
  subdomain_active_dns_brute?: boolean;
  subdomain_resolve?: boolean;
  subdomain_probe_http?: boolean;
  
  // Parameter discovery options
  param_crawl_depth?: number;
  param_test_reflection?: boolean;
  param_test_open_redirect?: boolean;
  param_max_pages?: number;
}

export interface ModuleError {
  module: string;
  message: string;
}

export interface ScanResult {
  target: string;
  mode?: ScanMode;
  started_at: string;
  finished_at: string;
  duration_seconds?: number;
  
  // Existing modules
  http?: HTTPResult;
  dns?: DNSReport;
  ports?: PortFinding[];
  tls?: TLSFinding[];
  headers?: HeadersReport;
  tech?: TechFinding[];
  cms?: CMSFinding[];
  dirs?: DirFinding[];
  vuln?: VulnReport;
  risk?: RiskReport;
  
  // New security modules
  subdomains?: SubdomainResult;
  parameters?: ParameterResult;
  auth?: AuthResult;
  api?: APIResult;
  cors?: CORSResult;
  injections?: InjectionSignalsResult;
  
  risk_summary?: RiskSummary;
  errors?: ModuleError[];
}

// New module result types
export interface SubdomainResult {
  subdomains: SubdomainInfo[];
  total: number;
  live: number;
  wildcards: string[];
  execution_time_ms: number;
}

export interface SubdomainInfo {
  name: string;
  ipv4?: string[];
  ipv6?: string[];
  cname?: string;
  live: boolean;
  status_code?: number;
  title?: string;
  content_type?: string;
  server_header?: string;
  source: string;
  fingerprint: string;
}

export interface ParameterResult {
  endpoints: Endpoint[];
  parameters: ParameterInfo[];
  reflection_candidates: ReflectionFinding[];
  open_redirect_hints: RedirectHint[];
  execution_time_ms: number;
}

export interface Endpoint {
  url: string;
  method: string;
  form?: FormInfo;
  js_endpoints?: string[];
  parameters: string[];
}

export interface FormInfo {
  action: string;
  method: string;
  inputs: FormInputField[];
}

export interface FormInputField {
  name: string;
  type: string;
  value?: string;
  placeholder?: string;
}

export interface ParameterInfo {
  name: string;
  sources: string[];
  locations: string[];
  type?: string;
}

export interface ReflectionFinding {
  url: string;
  parameter: string;
  reflection_type: string;
  confidence: string;
  payload: string;
  evidence: string;
}

export interface RedirectHint {
  url: string;
  parameter: string;
  evidence: string;
  confidence: string;
}

export interface AuthResult {
  login_pages: LoginPage[];
  session_issues: SessionIssue[];
  idor_candidates: IDORCandidate[];
  execution_time_ms: number;
}

export interface LoginPage {
  url: string;
  form_action: string;
  input_fields: string[];
  auth_type: string;
}

export interface SessionIssue {
  type: string;
  severity: string;
  cookie: string;
  evidence: string;
}

export interface IDORCandidate {
  url: string;
  parameter: string;
  id_type: string;
  similarity: number;
  evidence: string;
  confidence: string;
}

export interface APIResult {
  swagger_endpoints: string[];
  graphql_endpoints: string[];
  api_endpoints: APIEndpoint[];
  execution_time_ms: number;
}

export interface APIEndpoint {
  url: string;
  method: string;
  auth_required: boolean;
  parameters: string[];
  source: string;
}

export interface CORSResult {
  findings: CORSFinding[];
  execution_time_ms: number;
}

export interface CORSFinding {
  url: string;
  allow_origin: string;
  allow_credentials: boolean;
  exploitable: boolean;
  severity: string;
  exploitability_notes: string;
}

export interface InjectionSignalsResult {
  sqli_signals: InjectionSignal[];
  xss_signals: InjectionSignal[];
  execution_time_ms: number;
}

export interface InjectionSignal {
  url: string;
  parameter: string;
  type: string;
  confidence: string;
  evidence: string;
  payload: string;
}

export interface RiskSummary {
  overall_score: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  audit_summary: string;
  bug_bounty_summary: string;
  opportunities_list?: BugBountyOpportunity[];
}

export interface BugBountyOpportunity {
  title: string;
  severity: string;
  description: string;
  evidence: string;
  location: string;
  proof?: string;
}

export interface HTTPResult {
  url: string;
  status: number;
  title: string;
  headers: Record<string, string>;
  final_url: string;
}

export interface DNSReport {
  target: string;
  hostname?: string;
  ips?: string[];
  cname?: string[];
  mx?: DNSMXRecord[];
  ns?: string[];
  reverse_ptr?: DNSPTR[];
}

export interface DNSMXRecord {
  host: string;
  pref: number;
}

export interface DNSPTR {
  ip: string;
  ptr?: string[];
}

export interface PortFinding {
  port: number;
  status: string;
  service?: string;
  banner?: string;
  notes?: string;
}

export interface TLSFinding {
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
}

export interface HeadersReport {
  score: number;
  findings: HeaderFinding[];
  recommendations?: string[];
}

export interface HeaderFinding {
  name: string;
  status: string;
  severity: string;
  evidence?: string;
}

export interface TechFinding {
  name: string;
  version?: string;
  category?: string;  // AGREGAR ESTE CAMPO
  confidence: number;
  evidence: string;
}

export interface CMSFinding {
  name: string;
  version?: string;  // Ya existe pero asegúrate que esté
  confidence: number;
  evidence: string[];
}

export interface DirFinding {
  url: string;
  status: number;
  kind: string;
  evidence: string;
}

export interface VulnReport {
  components: Component[];
  findings: VulnFinding[];
  notes?: string[];
}

export interface Component {
  name: string;
  version?: string;
  ecosystem?: string;
  confidence: string;
  evidence: string;
}

export interface VulnFinding {
  id: string;
  component: string;
  version?: string;
  ecosystem?: string;
  severity?: string;
  summary?: string;
  confidence: string;
  evidence: string;
  recommendation: string;
}

export interface RiskReport {
  score: number;
  summary: string;
  findings: RiskFinding[];
}

export interface RiskFinding {
  id: string;
  severity: string;
  title: string;
  impact: string;
  evidence?: string;
  recommendation: string;
}
