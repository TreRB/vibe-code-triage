// VC7 — Hardcoded secret in committed file.
//
// Grep tracked text files for well-known secret prefixes. Skip .env* files
// (those are user secrets but flagged separately by VC9 if committed).

const SECRET_PATTERNS = [
  { name: "Stripe live secret key", re: /\bsk_live_[A-Za-z0-9]{16,}\b/, severity: "critical" },
  { name: "Stripe test secret key", re: /\bsk_test_[A-Za-z0-9]{16,}\b/, severity: "high" },
  { name: "Stripe restricted key",  re: /\brk_live_[A-Za-z0-9]{16,}\b/, severity: "critical" },
  { name: "GitHub personal access token (classic)", re: /\bghp_[A-Za-z0-9]{30,}\b/, severity: "critical" },
  { name: "GitHub OAuth access token", re: /\bgho_[A-Za-z0-9]{30,}\b/, severity: "critical" },
  { name: "GitHub user-to-server token", re: /\bghu_[A-Za-z0-9]{30,}\b/, severity: "critical" },
  { name: "GitHub server-to-server token", re: /\bghs_[A-Za-z0-9]{30,}\b/, severity: "critical" },
  { name: "GitHub refresh token", re: /\bghr_[A-Za-z0-9]{30,}\b/, severity: "critical" },
  { name: "GitLab PAT", re: /\bglpat-[A-Za-z0-9_-]{20,}\b/, severity: "critical" },
  { name: "Slack bot token", re: /\bxoxb-[A-Za-z0-9-]{10,}\b/, severity: "high" },
  { name: "Slack user token", re: /\bxoxp-[A-Za-z0-9-]{10,}\b/, severity: "high" },
  { name: "Slack app token",  re: /\bxapp-[A-Za-z0-9-]{10,}\b/, severity: "high" },
  { name: "AWS access key ID", re: /\bAKIA[0-9A-Z]{16}\b/, severity: "critical" },
  { name: "AWS temporary access key ID", re: /\bASIA[0-9A-Z]{16}\b/, severity: "high" },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_\-]{35}\b/, severity: "high" },
  { name: "OpenAI secret key", re: /\bsk-[A-Za-z0-9]{32,}\b/, severity: "critical" },
  { name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_\-]{32,}\b/, severity: "critical" },
  { name: "Clerk secret key", re: /\bsk_(?:test|live)_[A-Za-z0-9]{24,}\b/, severity: "critical" },
  { name: "Clerk publishable key", re: /\bpk_(?:test|live)_[A-Za-z0-9]{24,}\b/, severity: "medium" },
  { name: "Supabase service role JWT", re: /\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b/, severity: "high" },
  { name: "Generic long JWT", re: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b/, severity: "medium" },
  { name: "Twilio account SID", re: /\bAC[a-f0-9]{32}\b/, severity: "medium" },
  { name: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/, severity: "critical" },
  { name: "Mailgun API key", re: /\bkey-[a-z0-9]{32}\b/, severity: "high" },
  { name: "Vercel API token", re: /\bvercel_[A-Za-z0-9]{24,}\b/, severity: "high" },
  { name: "npm automation token", re: /\bnpm_[A-Za-z0-9]{36}\b/, severity: "critical" },
  { name: "Hugging Face token", re: /\bhf_[A-Za-z0-9]{30,}\b/, severity: "high" }
];

function isEnvFile(relPath) {
  const base = relPath.split("/").pop() || "";
  return base === ".env" || base.startsWith(".env.") || relPath.endsWith("/.env.example");
}

function isLockFile(relPath) {
  const b = relPath.split("/").pop() || "";
  return b === "package-lock.json" || b === "pnpm-lock.yaml" || b === "yarn.lock" || b === "bun.lockb" || b === "bun.lock";
}

function isBinary(relPath) {
  const lower = relPath.toLowerCase();
  return lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg")
    || lower.endsWith(".webp") || lower.endsWith(".gif") || lower.endsWith(".ico")
    || lower.endsWith(".pdf") || lower.endsWith(".zip") || lower.endsWith(".woff")
    || lower.endsWith(".woff2") || lower.endsWith(".ttf") || lower.endsWith(".mp4");
}

function lineNumberAt(content, idx) {
  let line = 1;
  for (let i = 0; i < idx && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

function isExampleContext(lineText, matchText) {
  // Examine only the line text OUTSIDE the match itself, since some real
  // secret formats happen to embed the word "example" (e.g., the classic
  // AWS docs key AKIAIOSFODNN7EXAMPLE — still a leak-shaped pattern you
  // want to report).
  const outside = (typeof matchText === "string" && lineText.includes(matchText))
    ? lineText.replace(matchText, " ")
    : lineText;
  const l = outside.toLowerCase();
  return l.includes("example") || l.includes("placeholder") || l.includes("dummy")
    || l.includes("your-") || l.includes("xxxx") || l.includes("<replace")
    || l.includes("fake")
    || / \/\/ ?e\.g\./.test(l)
    || l.includes("sample");
}

export default {
  id: "VC7",
  title: "Hardcoded secret in committed file",
  severity: "critical",
  run({ index }) {
    const findings = [];

    for (const f of index.files) {
      if (!f.content) continue;
      if (isEnvFile(f.relPath)) continue;
      if (isLockFile(f.relPath)) continue;
      if (isBinary(f.relPath)) continue;

      const claimed = []; // [start, end] ranges already reported to dedupe overlaps
      for (const pat of SECRET_PATTERNS) {
        pat.re.lastIndex = 0;
        const re = new RegExp(pat.re.source, "g");
        let m;
        while ((m = re.exec(f.content)) !== null) {
          const hitStart = m.index;
          const hitEnd = m.index + m[0].length;
          if (claimed.some(([s, e]) => !(hitEnd <= s || hitStart >= e))) continue;
          claimed.push([hitStart, hitEnd]);
          const line = lineNumberAt(f.content, m.index);
          const lineStart = f.content.lastIndexOf("\n", m.index - 1) + 1;
          const lineEnd = f.content.indexOf("\n", m.index);
          const lineText = f.content.slice(lineStart, lineEnd === -1 ? f.content.length : lineEnd);
          const sample = m[0];
          if (isExampleContext(lineText, sample)) continue;

          const redacted = sample.slice(0, 6) + "…" + sample.slice(-4);
          findings.push({
            severity: pat.severity,
            file: f.relPath,
            line,
            title: `Hardcoded ${pat.name}`,
            evidence: `${f.relPath}:${line} contains a ${pat.name} matching /${pat.re.source}/ -> ${redacted}`,
            fix: `Move the secret to an env var read from process.env at runtime. Rotate the key immediately — assume it is compromised since it's in source control.`,
            data: { match: redacted }
          });
        }
      }
    }

    return findings;
  }
};
