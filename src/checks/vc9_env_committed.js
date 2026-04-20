// VC9 — .env file committed.
//
// Flag CRITICAL when .env / .env.local / .env.production / .env.development
// / .env.staging is present AT THE REPO ROOT (or immediately under common
// subpaths). .env.example / .env.sample / .env.template are always fine.

const DANGER = new Set([
  ".env",
  ".env.local",
  ".env.production",
  ".env.production.local",
  ".env.development",
  ".env.development.local",
  ".env.staging",
  ".env.staging.local",
  ".env.test.local"
]);

const SAFE_EXAMPLE = /\.env\.(example|sample|template|dist|defaults)$/i;

export default {
  id: "VC9",
  title: ".env file committed",
  severity: "critical",
  run({ index }) {
    const findings = [];

    for (const f of index.files) {
      const base = f.relPath.split("/").pop() || "";
      if (SAFE_EXAMPLE.test(base)) continue;
      if (!DANGER.has(base)) continue;

      // Evidence: sample a couple of env-key-looking lines (but redact values).
      let evidence = `${f.relPath} is tracked in the working tree. If this is in git history, every secret here is compromised — rotate all of them.`;
      if (f.content) {
        const lines = f.content.split(/\r?\n/).slice(0, 40);
        const keys = [];
        for (const ln of lines) {
          const m = ln.match(/^\s*([A-Z][A-Z0-9_]+)\s*=\s*.+$/);
          if (m) keys.push(m[1]);
        }
        if (keys.length) {
          evidence += ` Detected keys: ${keys.slice(0, 10).join(", ")}${keys.length > 10 ? `, …(+${keys.length - 10} more)` : ""}.`;
        }
      }

      findings.push({
        severity: "critical",
        file: f.relPath,
        line: 1,
        title: `Committed env file: ${base}`,
        evidence,
        fix: `Add "${base}" (or ".env*" except ".env.example") to .gitignore, run 'git rm --cached ${f.relPath}', commit, then rotate every secret currently in the file. If the repo is public, assume scraped — rotate first.`
      });
    }

    return findings;
  }
};
