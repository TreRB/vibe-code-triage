// VC1 — Supabase RLS disabled in migration SQL.
//
// For every CREATE TABLE found under supabase/migrations/*.sql (or generic
// migrations/*.sql), check that somewhere in the same migration set there's
// an ALTER TABLE <name> ENABLE ROW LEVEL SECURITY for it. Flag CRITICAL per
// missing table.

const CREATE_TABLE = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?(?<schema>[a-zA-Z_][\w]*)"?\.)?"?(?<name>[a-zA-Z_][\w]*)"?/gi;
const ENABLE_RLS = /alter\s+table\s+(?:"?(?<schema>[a-zA-Z_][\w]*)"?\.)?"?(?<name>[a-zA-Z_][\w]*)"?\s+enable\s+row\s+level\s+security/gi;

function isMigration(relPath) {
  const p = relOrLower(relPath);
  if (!p.endsWith(".sql")) return false;
  return p.includes("supabase/migrations/") || p.includes("/migrations/") || p.startsWith("migrations/");
}

function relOrLower(p) { return p.toLowerCase(); }

function getLine(content, idx) {
  let line = 1;
  for (let i = 0; i < idx && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

export default {
  id: "VC1",
  title: "Supabase RLS disabled",
  severity: "critical",
  run({ index }) {
    const findings = [];

    const migrationFiles = index.files.filter((f) => isMigration(f.relPath) && f.content != null);
    if (migrationFiles.length === 0) return findings;

    // Build the set of tables that have RLS enabled anywhere in the
    // migration tree. This has to be global because the CREATE and the
    // ALTER ... ENABLE RLS may live in different files.
    const rlsEnabled = new Set(); // key: schema.name (lowercase)
    for (const f of migrationFiles) {
      let m;
      ENABLE_RLS.lastIndex = 0;
      while ((m = ENABLE_RLS.exec(f.content)) !== null) {
        const schema = (m.groups.schema || "public").toLowerCase();
        const name = m.groups.name.toLowerCase();
        rlsEnabled.add(`${schema}.${name}`);
      }
    }

    // Now find CREATE TABLE occurrences and flag any without a matching
    // ENABLE RLS.
    const flagged = new Set();
    for (const f of migrationFiles) {
      let m;
      CREATE_TABLE.lastIndex = 0;
      while ((m = CREATE_TABLE.exec(f.content)) !== null) {
        const schema = (m.groups.schema || "public").toLowerCase();
        const name = m.groups.name.toLowerCase();
        const key = `${schema}.${name}`;
        if (rlsEnabled.has(key)) continue;
        if (flagged.has(key)) continue;
        flagged.add(key);
        const line = getLine(f.content, m.index);
        findings.push({
          severity: "critical",
          file: f.relPath,
          line,
          title: `RLS not enabled on table "${schema}.${name}"`,
          evidence: `CREATE TABLE for ${schema}.${name} found at ${f.relPath}:${line} but no matching "ALTER TABLE ${name} ENABLE ROW LEVEL SECURITY" anywhere in migrations.`,
          fix: `Add: ALTER TABLE ${schema === "public" ? "" : schema + "."}"${name}" ENABLE ROW LEVEL SECURITY; plus a CREATE POLICY restricting rows to auth.uid(). Until you do, anyone with the anon key can read/write every row.`
        });
      }
    }

    return findings;
  }
};
