import type { ScanRequest, ScanResult } from "./types";

// Endpoint para la función de escaneo
const scanEndpoint = import.meta.env.PROD
  ? "/.netlify/functions/scan"
  : `${import.meta.env.VITE_API_BASE_URL || "http://localhost:8080"}/scan`;

export async function scanTarget(payload: ScanRequest): Promise<ScanResult> {
  const response = await fetch(scanEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  return response.json();
}
