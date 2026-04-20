// VC3 — Service-role key exposed in client-side file.
//
// Flag CRITICAL when SUPABASE_SERVICE_ROLE_KEY is referenced from a file
// under app/, pages/, components/, or src/ that is NOT also under an
// api/ or server/ subtree. Also flag NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY
// anywhere (the NEXT_PUBLIC_ prefix always makes it client-exposed).

const SERVICE_ROLE = /SUPABASE_SERVICE_ROLE_KEY/g;
const NEXT_PUBLIC_SRK = /NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY/g;

const CLIENT_ROOTS = ["app/", "pages/", "components/", "src/"];

function isClientPath(relPath) {
  // Anything under app/ or pages/ is client unless it's api/ or server/.
  const p = relPath.toLowerCase();
  // Treat anything under "/api/" or "/server/" as server-side.
  if (p.includes("/api/") || p.startsWith("api/")) return false;
  if (p.includes("/server/") || p.startsWith("server/")) return false;
  // route.ts handlers in app/api/ are covered above. Middleware.ts runs
  // server-side but not user-facing — still we only care about client
  // bundle exposure here.
  if (p.endsWith("middleware.ts") || p.endsWith("middleware.js")) return false;
  for (const r of CLIENT_ROOTS) {
    if (p === r.slice(0, -1) || p.startsWith(r)) return true;
  }
  return false;
}

function isCodeFile(relPath) {
  const lower = relPath.toLowerCase();
  return lower.endsWith(".ts") || lower.endsWith(".tsx")
    || lower.endsWith(".js") || lower.endsWith(".jsx")
    || lower.endsWith(".mjs") || lower.endsWith(".cjs");
}

function lineNumberAt(content, idx) {
  let line = 1;
  for (let i = 0; i < idx && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

export default {
  id: "VC3",
  title: "Service-role key exposed to client",
  severity: "critical",
  run({ index }) {
    const findings = [];

    for (const f of index.files) {
      if (!f.content) continue;
      if (!isCodeFile(f.relPath)) continue;

      // NEXT_PUBLIC_ flavour is always critical regardless of path.
      NEXT_PUBLIC_SRK.lastIndex = 0;
      let m;
      while ((m = NEXT_PUBLIC_SRK.exec(f.content)) !== null) {
        findings.push({
          severity: "critical",
          file: f.relPath,
          line: lineNumberAt(f.content, m.index),
          title: "Service-role key referenced via NEXT_PUBLIC_ env var",
          evidence: `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY referenced at ${f.relPath}. Next.js inlines any NEXT_PUBLIC_* env var into the client bundle — this leaks the full-access service-role key to every page visitor.`,
          fix: `Rename to SUPABASE_SERVICE_ROLE_KEY (no NEXT_PUBLIC_ prefix), read only from server code, rotate the key in Supabase dashboard immediately — current key is burned.`
        });
      }

      if (!isClientPath(f.relPath)) continue;

      SERVICE_ROLE.lastIndex = 0;
      while ((m = SERVICE_ROLE.exec(f.content)) !== null) {
        // Skip the NEXT_PUBLIC_ match since that's already flagged.
        const start = m.index - "NEXT_PUBLIC_".length;
        if (start >= 0 && f.content.slice(start, start + "NEXT_PUBLIC_".length) === "NEXT_PUBLIC_") {
          continue;
        }
        findings.push({
          severity: "critical",
          file: f.relPath,
          line: lineNumberAt(f.content, m.index),
          title: "SUPABASE_SERVICE_ROLE_KEY referenced from client-side file",
          evidence: `SUPABASE_SERVICE_ROLE_KEY imported into ${f.relPath} which is a client-rendered path (under app/, pages/, components/, or src/ with no /api/ or /server/ segment). Anything imported here is bundled and shipped to browsers.`,
          fix: `Move Supabase service-role-key usage into a server-only module (app/api/*/route.ts, server/*, or a "use server" action). Rotate the key in Supabase — it must be assumed leaked.`
        });
      }
    }

    return findings;
  }
};
