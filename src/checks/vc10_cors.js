// VC10 — Dangerous default CORS.
//
// Flag MEDIUM when a source file:
//  (a) sets Access-Control-Allow-Origin: * AND any of:
//      - Access-Control-Allow-Credentials: true (browsers reject this combo,
//        but many servers still return it — it's the signature of copy-paste
//        CORS and often paired with credential-carrying fetch from clients);
//      - a credential-carrying fetch elsewhere in the file
//        (fetch(..., { credentials: 'include' }) or withCredentials: true);
//  (b) uses cors({ origin: true }) / cors({ origin: "*", credentials: true }).

const ORIGIN_STAR = /Access-Control-Allow-Origin['"\s:,]+\*/i;
const CREDS_TRUE  = /Access-Control-Allow-Credentials['"\s:,]+true/i;
const FETCH_WITH_CREDS = /credentials\s*:\s*['"]include['"]/;
const XHR_WITH_CREDS = /withCredentials\s*=\s*true/;
const CORS_ORIGIN_TRUE = /cors\s*\(\s*\{[^}]*origin\s*:\s*true/;
const CORS_STAR_WITH_CREDS = /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"][^}]*credentials\s*:\s*true/;
const RES_SETHEADER_STAR = /setHeader\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]\s*\)/i;

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
  id: "VC10",
  title: "Dangerous default CORS",
  severity: "medium",
  run({ index }) {
    const findings = [];
    const seen = new Set();

    for (const f of index.files) {
      if (!f.content) continue;
      if (!isCodeFile(f.relPath)) continue;

      const hasStarOrigin = ORIGIN_STAR.test(f.content) || RES_SETHEADER_STAR.test(f.content);
      const hasCreds = CREDS_TRUE.test(f.content);
      const hasFetchCreds = FETCH_WITH_CREDS.test(f.content) || XHR_WITH_CREDS.test(f.content);
      const corsOriginTrue = CORS_ORIGIN_TRUE.test(f.content);
      const corsStarCreds = CORS_STAR_WITH_CREDS.test(f.content);

      const buildFinding = (match, title, evidence) => {
        const line = lineNumberAt(f.content, match.index || 0);
        const key = `${f.relPath}:${title}`;
        if (seen.has(key)) return;
        seen.add(key);
        findings.push({
          severity: "medium",
          file: f.relPath,
          line,
          title,
          evidence,
          fix: `Replace the wildcard with an allowlist of trusted origins. If you need cookies/auth across origins, you MUST echo the exact Origin back (not '*') and only for allowlisted ones. Never combine '*' with credentials.`
        });
      };

      if (corsStarCreds) {
        const m = CORS_STAR_WITH_CREDS.exec(f.content) || { index: 0 };
        buildFinding(m, "cors() with origin '*' AND credentials: true", `${f.relPath} configures CORS with origin '*' and credentials: true — browsers ignore the cookies in this combo, but the pattern indicates the author intended cross-origin credential access.`);
        continue;
      }

      if (corsOriginTrue) {
        const m = CORS_ORIGIN_TRUE.exec(f.content) || { index: 0 };
        buildFinding(m, "cors() with origin: true (reflects arbitrary Origin)", `${f.relPath} calls cors({ origin: true, ... }) which echoes whatever Origin the attacker sends. Combined with credentials: true this is a full account-takeover primitive.`);
        continue;
      }

      if (hasStarOrigin && (hasCreds || hasFetchCreds)) {
        const m = ORIGIN_STAR.exec(f.content) || RES_SETHEADER_STAR.exec(f.content) || { index: 0 };
        buildFinding(m, "Access-Control-Allow-Origin: * combined with credentials", `${f.relPath} sets Access-Control-Allow-Origin: * and also ${hasCreds ? "Access-Control-Allow-Credentials: true" : "uses credential-carrying fetch (credentials: 'include' / withCredentials)"}. This is the classic copy-paste CORS footgun.`);
      }
    }

    return findings;
  }
};
