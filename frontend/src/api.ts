import type { ScanRequest, ScanResult } from "./types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";

export async function scanTarget(request: ScanRequest): Promise<ScanResult> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 600000); // 10 minutos

  try {
    const response = await fetch(`${API_BASE_URL}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const text = await response.text();
      let errorMsg = `HTTP ${response.status}`;
      
      try {
        const data = JSON.parse(text);
        if (data && data.error) {
          errorMsg = data.error;
        }
      } catch {
        // Si no es JSON válido, usa el status code
      }
      
      throw new Error(errorMsg);
    }

    return await response.json();
  } catch (error: any) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new Error('Timeout: el escaneo tardó más de 10 minutos');
    }
    throw error;
  }
}
