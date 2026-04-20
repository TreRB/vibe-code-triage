// Proper CORS: explicit allowlist, no wildcard.
const ALLOW = new Set(["https://example.com", "https://app.example.com"]);

export function corsHeadersFor(origin: string | null) {
  if (!origin || !ALLOW.has(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Vary": "Origin"
  };
}
