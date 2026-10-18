// In dev, Vite proxies /api to FastAPI. In the Docker image FastAPI serves this UI itself,
// so the API lives at the same origin.
const BASE = import.meta.env.DEV ? "/api" : "";

let tenant = "public";
export const setTenant = (t) => { tenant = t || "public"; };
export const getTenant = () => tenant;

export async function api(path, { method = "GET", body, params } = {}) {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  const res = await fetch(`${BASE}${path}${qs}`, {
    method,
    headers: { "Content-Type": "application/json", "X-Tenant": tenant },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON error body */ }
  if (!res.ok) {
    const detail = data?.detail || data?.error || res.statusText;
    // Fail loudly: surface the server's reason, never an empty result.
    throw new Error(`${res.status} ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
  }
  return data;
}
