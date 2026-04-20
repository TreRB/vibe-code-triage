// VC5 — Next.js route handler missing auth.
//
// Walk route handlers under app/api/**/route.ts and pages/api/**.
// If the handler writes to a DB (insert/update/delete/upsert calls, or
// Prisma/Drizzle/Supabase write method names) AND has no recognisable
// auth call, flag HIGH.
// If it's read-only but returns likely-sensitive fields, flag MEDIUM.

const AUTH_HINTS = [
  /\bauth\s*\(\s*\)/,               // Clerk auth()
  /\bawait\s+auth\s*\(/,
  /\bgetAuth\s*\(/,                 // Clerk getAuth(req)
  /\bcurrentUser\s*\(/,              // Clerk currentUser()
  /\bgetServerSession\s*\(/,         // next-auth
  /\bgetSession\s*\(/,               // next-auth / generic
  /\bcreateRouteHandlerClient\b/,    // Supabase SSR — usually paired with session check
  /\bsupabase\.auth\.(?:getUser|getSession)\s*\(/,
  /\bverifyToken\s*\(/,
  /\brequireUser\s*\(/,
  /\brequireAuth\s*\(/,
  /\bclerkMiddleware\s*\(/,
  /\bwithAuth\s*\(/,
  /\bfrom\s+["']@clerk\//            // importing clerk — weak signal, but we combine
];

const WRITE_HINTS = [
  /\.insert\s*\(/,
  /\.update\s*\(/,
  /\.upsert\s*\(/,
  /\.delete\s*\(/,
  /\.create\s*\(/,        // Prisma: prisma.user.create
  /\.createMany\s*\(/,
  /\.updateMany\s*\(/,
  /\.deleteMany\s*\(/,
  /\bprisma\.\w+\.(create|update|delete|upsert)/,
  /\bdb\.(insert|update|delete)/,     // drizzle
  /\.signUp\s*\(/                     // Supabase auth signUp outside of sign-up route
];

const SENSITIVE_RETURN = /\b(user|users|profile|profiles|subscription|subscriptions|admin|customer|customers|payment|payments|order|orders|invoice|invoices|stripe_customer|email|phone|address|billing|secret|api_key|token)\b/i;

const EXPORT_METHOD_RE = /\bexport\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b/g;
const PAGES_HANDLER_RE = /\bexport\s+default\s+(?:async\s+)?function\s+handler\b/;

function isAppRouteHandler(relPath) {
  const p = relPath.toLowerCase();
  if (!(p.endsWith("/route.ts") || p.endsWith("/route.tsx") || p.endsWith("/route.js") || p.endsWith("/route.mjs"))) return false;
  return p.includes("/api/") || p.includes("app/api/");
}

function isPagesApiHandler(relPath) {
  const p = relPath.toLowerCase();
  if (!(p.endsWith(".ts") || p.endsWith(".tsx") || p.endsWith(".js"))) return false;
  return p.startsWith("pages/api/") || p.includes("/pages/api/");
}

function anyMatch(content, patterns) {
  for (const re of patterns) {
    if (re.test(content)) return true;
  }
  return false;
}

export default {
  id: "VC5",
  title: "Next.js route handler missing auth",
  severity: "high",
  run({ index }) {
    const findings = [];

    for (const f of index.files) {
      if (!f.content) continue;
      const app = isAppRouteHandler(f.relPath);
      const pages = isPagesApiHandler(f.relPath);
      if (!app && !pages) continue;

      // Skip obviously-public endpoints (webhooks, health checks,
      // Stripe/Clerk webhooks do signature verification instead of auth).
      const pathLower = f.relPath.toLowerCase();
      if (pathLower.includes("/webhook") || pathLower.includes("webhooks/")) continue;
      if (pathLower.includes("/health") || pathLower.includes("/healthz") || pathLower.includes("/ping")) continue;

      const hasAuth = anyMatch(f.content, AUTH_HINTS);
      const writes = anyMatch(f.content, WRITE_HINTS);
      const sensitiveRead = SENSITIVE_RETURN.test(f.content);

      // Find declared methods (GET, POST, etc) to make evidence specific.
      const methods = new Set();
      EXPORT_METHOD_RE.lastIndex = 0;
      let m;
      while ((m = EXPORT_METHOD_RE.exec(f.content)) !== null) {
        methods.add(m[1]);
      }
      if (pages && PAGES_HANDLER_RE.test(f.content)) {
        methods.add("ANY");
      }

      if (methods.size === 0) continue; // not a real handler after all

      const methodList = [...methods].join(", ") || "?";

      if (writes && !hasAuth) {
        findings.push({
          severity: "high",
          file: f.relPath,
          line: 1,
          title: `Route ${methodList} handler writes to DB without auth`,
          evidence: `Handler at ${f.relPath} exports ${methodList} and contains write calls (insert/update/delete/upsert/create) but no auth()/getAuth()/currentUser()/getSession()/supabase.auth.getUser() call.`,
          fix: `Gate the handler with: const { userId } = await auth(); if (!userId) return new Response("unauthorized", { status: 401 });  then filter writes by userId.`
        });
      } else if (!hasAuth && sensitiveRead && (methods.has("GET") || methods.has("ANY"))) {
        findings.push({
          severity: "medium",
          file: f.relPath,
          line: 1,
          title: `Route ${methodList} handler exposes sensitive fields without auth`,
          evidence: `Handler at ${f.relPath} references user/profile/subscription/admin data and has no auth() / getAuth() / currentUser() / getSession() call.`,
          fix: `Add an auth gate and filter results by the caller's user id. If the endpoint is intentionally public, narrow the response to non-sensitive columns.`
        });
      }
    }

    return findings;
  }
};
