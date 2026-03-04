import type { ScanRequest, ScanResult } from "./types";

// Ya NO usamos VITE_API_BASE_URL
const API_BASE_URL = "/api"; // Proxy local en Netlify

export async function scanTarget(payload: ScanRequest): Promise<ScanResult> {
  const response = await fetch(`${API_BASE_URL}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  return response.json();
}
