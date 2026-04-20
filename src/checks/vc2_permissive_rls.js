// VC2 — Permissive RLS policy.
//
// Walk migration SQL files. For every CREATE POLICY statement, inspect
// the USING clause. Flag HIGH on USING (true) or
// USING (auth.role() = 'authenticated') or a missing USING clause.

const POLICY_BLOCK = /create\s+policy\s+[^;]*?on\s+(?:"?(?<schema>[a-zA-Z_][\w]*)"?\.)?"?(?<table>[a-zA-Z_][\w]*)"?[^;]*?;/gis;

// Extract the argument to USING(...) allowing balanced nested parens.
function extractUsingClause(block) {
  const re = /\busing\s*\(/i;
  const m = block.match(re);
  if (!m) return null;
  const start = (m.index || 0) + m[0].length;
  let depth = 1;
  for (let i = start; i < block.length; i++) {
    const c = block[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return block.slice(start, i);
    }
  }
  return null;
}

function isMigration(relPath) {
  const p = relPath.toLowerCase();
  if (!p.endsWith(".sql")) return false;
  return p.includes("supabase/migrations/") || p.includes("/migrations/") || p.startsWith("migrations/");
}

function getLine(content, idx) {
  let line = 1;
  for (let i = 0; i < idx && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

export default {
  id: "VC2",
  title: "Permissive RLS policy",
  severity: "high",
  run({ index }) {
    const findings = [];
    const migrationFiles = index.files.filter((f) => isMigration(f.relPath) && f.content != null);

    for (const f of migrationFiles) {
      let m;
      POLICY_BLOCK.lastIndex = 0;
      while ((m = POLICY_BLOCK.exec(f.content)) !== null) {
        const block = m[0];
        const line = getLine(f.content, m.index);
        const table = m.groups.table;
        const usingRaw = extractUsingClause(block);

        if (usingRaw == null) {
          // No USING clause on a SELECT/USING-applicable policy.
          // Only flag if block references SELECT/UPDATE/DELETE/ALL
          // (INSERT policies use WITH CHECK and are fine without USING).
          const op = (block.match(/\bfor\s+(select|update|delete|all)\b/i) || [])[0];
          if (op) {
            findings.push({
              severity: "high",
              file: f.relPath,
              line,
              title: `RLS policy on "${table}" has no USING clause`,
              evidence: `CREATE POLICY without USING(...) clause for ${op}. On some Postgres/Supabase versions this defaults to permissive.`,
              fix: `Add an explicit USING clause: e.g., USING (owner_id = auth.uid()).`
            });
          }
          continue;
        }

        const usingExpr = usingRaw.trim().toLowerCase();

        if (/^true$/.test(usingExpr) || /^\(\s*true\s*\)$/.test(usingExpr)) {
          findings.push({
            severity: "high",
            file: f.relPath,
            line,
            title: `RLS policy on "${table}" uses USING (true)`,
            evidence: `USING (true) allows every row through. Any authenticated or anon request with this policy active can read/write every row.`,
            fix: `Replace USING (true) with an ownership predicate: USING (owner_id = auth.uid()) or similar.`
          });
          continue;
        }

        if (/auth\.role\(\)\s*=\s*['"]authenticated['"]/.test(usingExpr)
            && !/auth\.uid/.test(usingExpr)
            && !/user_id|owner_id|created_by|tenant_id/.test(usingExpr)) {
          findings.push({
            severity: "high",
            file: f.relPath,
            line,
            title: `RLS policy on "${table}" only checks auth.role() = 'authenticated'`,
            evidence: `Any logged-in user — on any tenant — can read/write every row in ${table}. This is the Lovable/v0 default and the #1 cross-tenant data leak source in AI-generated SaaS.`,
            fix: `Add per-row ownership: USING (auth.role() = 'authenticated' AND owner_id = auth.uid()).`
          });
          continue;
        }
      }
    }

    return findings;
  }
};
