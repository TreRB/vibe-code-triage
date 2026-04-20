// VC8 — Missing CSRF / open POST endpoint.
//
// For every Next.js route handler (app/api/*/route.ts or pages/api/*) that
// exports a POST/PUT/PATCH/DELETE handler AND appears to mutate state,
// look for *any* CSRF indicator (CSRF token check, SameSite cookie,
// Turnstile / hCaptcha verification, origin check, Clerk auth() in handler,
// authorization header check, or webhook signature). If none found, flag
// MEDIUM.
//
// Rationale: A vibe-coded POST endpoint with nothing but `await supabase
// .from(...).insert(body)` is the classic CSRF attack surface.

const HAS_POSTISH = /\bexport\s+(?:async\s+)?(?:function|const)\s+(POST|PUT|PATCH|DELETE)\b/;
const PAGES_HANDLER = /\bexport\s+default\s+(?:async\s+)?function\s+\w*handler\b/i;

const CSRF_INDICATORS = [
  /\bcsrfToken\b/i,
  /\bcsrf_token\b/i,
  /\bx-csrf-token\b/i,
  /\bcsrf\b.*?header/i,
  /\bsamesite[^\n]*\b(strict|lax)/i,
  /\bverifyTurnstile\b/i,
  /turnstile\.siteverify/i,
  /challenges\.cloudflare\.com\/turnstile/i,
  /\bhcaptcha\b/i,
  /hcaptcha\.com\/siteverify/i,
  /recaptcha\/api\/siteverify/i,
  /\breq\.headers\.origin\b/,
  /\brequest\.headers\.get\(['"]origin['"]\)/i,
  /\ballowedOrigins?\b/,
  /\bvalidateOrigin\b/i,
  /stripe\.webhooks\.constructEvent/,
  /svix\.verify/i,
  /\bclerkMiddleware\s*\(/,
  /\bwithAuth\s*\(/,
  /\bauth\s*\(\s*\)/,
  /\bgetAuth\s*\(/,
  /\bcurrentUser\s*\(/,
  /\bgetServerSession\s*\(/,
  /\bverifyToken\s*\(/,
  /\bauthorization\b[^\n]{0,40}bearer/i
];

const MUTATION_PATTERNS = [
  /\.insert\s*\(/,
  /\.update\s*\(/,
  /\.upsert\s*\(/,
  /\.delete\s*\(/,
  /\.create\s*\(/,
  /\bprisma\.\w+\.(create|update|delete|upsert)/,
  /\bdb\.(insert|update|delete)/,
  /\.save\s*\(/,
  /\.destroy\s*\(/,
  /fs\.(writeFile|appendFile|unlink|rename)/,
  /sendMail|sendgrid\.send|transport\.send/i
];

function isAppRoute(relPath) {
  const p = relPath.toLowerCase();
  if (!(p.endsWith("/route.ts") || p.endsWith("/route.tsx") || p.endsWith("/route.js") || p.endsWith("/route.mjs"))) return false;
  return p.includes("/api/") || p.includes("app/api/");
}

function isPagesApi(relPath) {
  const p = relPath.toLowerCase();
  if (!(p.endsWith(".ts") || p.endsWith(".tsx") || p.endsWith(".js"))) return false;
  return p.startsWith("pages/api/") || p.includes("/pages/api/");
}

function anyMatch(src, patterns) {
  for (const re of patterns) {
    if (re.test(src)) return true;
  }
  return false;
}

export default {
  id: "VC8",
  title: "POST endpoint without CSRF protection",
  severity: "medium",
  run({ index }) {
    const findings = [];

    for (const f of index.files) {
      if (!f.content) continue;
      const app = isAppRoute(f.relPath);
      const pages = isPagesApi(f.relPath);
      if (!app && !pages) continue;

      const pathLower = f.relPath.toLowerCase();
      // Signed webhooks handle their own verification — skip.
      if (pathLower.includes("/webhook") || pathLower.includes("webhooks/")) continue;

      const hasMutatingExport = HAS_POSTISH.test(f.content) || (pages && PAGES_HANDLER.test(f.content));
      if (!hasMutatingExport) continue;

      const mutates = anyMatch(f.content, MUTATION_PATTERNS);
      if (!mutates) continue;

      const hasCsrfIndicator = anyMatch(f.content, CSRF_INDICATORS);
      if (hasCsrfIndicator) continue;

      findings.push({
        severity: "medium",
        file: f.relPath,
        line: 1,
        title: "State-mutating POST endpoint with no CSRF / auth / origin check",
        evidence: `${f.relPath} exports a mutating handler (POST/PUT/PATCH/DELETE) that writes to DB / files / sends mail, but contains no recognised CSRF token, SameSite cookie enforcement, Turnstile/hCaptcha verification, origin check, webhook signature verify, or auth call. Any page on the open web can POST to this endpoint on behalf of a logged-in user.`,
        fix: `Pick one: (1) call auth()/getAuth() and verify userId, (2) enforce SameSite=Strict on the auth cookie + validate Origin, (3) add a double-submit CSRF token (e.g. @edge-csrf/nextjs), or (4) add Turnstile / hCaptcha.`
      });
    }

    return findings;
  }
};
