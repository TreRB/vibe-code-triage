// VC6 — AI-hallucinated / typosquat package.
//
// Parse package.json dependencies (+ devDependencies, peerDependencies).
// For each name:
//   1) Exact match in known-typosquats.json -> HIGH/MEDIUM per entry.
//   2) Not in top npm list, and Levenshtein <= 2 to a top-list name -> MEDIUM.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const KNOWN = JSON.parse(fs.readFileSync(path.join(__dirname, "../data/known-typosquats.json"), "utf8"));
const TOP = JSON.parse(fs.readFileSync(path.join(__dirname, "../data/npm-top5000.json"), "utf8"));
const TOP_SET = new Set(TOP.names);

export function levenshtein(a, b) {
  if (a === b) return 0;
  const la = a.length, lb = b.length;
  if (la === 0) return lb;
  if (lb === 0) return la;
  if (Math.abs(la - lb) > 3) return Math.abs(la - lb); // early bail for our use (<=2)
  // Single-row DP.
  let prev = new Array(lb + 1);
  let curr = new Array(lb + 1);
  for (let j = 0; j <= lb; j++) prev[j] = j;
  for (let i = 1; i <= la; i++) {
    curr[0] = i;
    for (let j = 1; j <= lb; j++) {
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,       // deletion
        curr[j - 1] + 1,   // insertion
        prev[j - 1] + cost // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }
  return prev[lb];
}

function findPackageJsons(index) {
  return index.files.filter((f) =>
    f.relPath === "package.json"
    || (f.relPath.endsWith("/package.json")
        && !f.relPath.includes("node_modules/"))
  );
}

function collectDeps(pkgJson) {
  const deps = {};
  for (const key of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
    if (pkgJson[key] && typeof pkgJson[key] === "object") {
      for (const [n, v] of Object.entries(pkgJson[key])) {
        deps[n] = deps[n] || { versions: new Set(), where: new Set() };
        deps[n].versions.add(v);
        deps[n].where.add(key);
      }
    }
  }
  return deps;
}

function closestTop(name) {
  let best = null, bestD = 999;
  for (const t of TOP_SET) {
    const d = levenshtein(name, t);
    if (d < bestD) {
      bestD = d;
      best = t;
      if (d === 0) break;
    }
  }
  return { name: best, distance: bestD };
}

export default {
  id: "VC6",
  title: "AI-hallucinated / typosquat package",
  severity: "high",
  run({ index }) {
    const findings = [];
    const pkgs = findPackageJsons(index);

    for (const f of pkgs) {
      if (!f.content) continue;
      let parsed;
      try { parsed = JSON.parse(f.content); }
      catch { continue; }
      const deps = collectDeps(parsed);

      for (const name of Object.keys(deps)) {
        // Skip scoped packages for Levenshtein (too many false positives),
        // but still match them in the known-typosquats map.
        const known = KNOWN.packages[name];
        if (known) {
          findings.push({
            severity: known.severity || "high",
            file: f.relPath,
            line: 1,
            title: `Suspicious dependency: "${name}"`,
            evidence: `${f.relPath} declares "${name}" (in ${[...deps[name].where].join(", ")}). ${known.note} Expected package: "${known.real}".`,
            fix: `Replace "${name}" with "${known.real}" in ${f.relPath}, remove node_modules, and run 'npm install'. Audit any install scripts that ran under the typosquat name.`,
            data: { name, suspected: "known-typosquat", real: known.real }
          });
          continue;
        }

        // Skip scoped packages — their @scope/ prefix dominates distance.
        if (name.startsWith("@")) continue;
        // Skip very short names (high FP rate).
        if (name.length < 4) continue;
        // Exact top-list hit — safe.
        if (TOP_SET.has(name)) continue;

        const { name: nearest, distance } = closestTop(name);
        if (nearest && distance > 0 && distance <= 2) {
          findings.push({
            severity: "medium",
            file: f.relPath,
            line: 1,
            title: `Possible typosquat: "${name}" (Levenshtein ${distance} to "${nearest}")`,
            evidence: `${f.relPath} declares "${name}" which differs by ${distance} character${distance === 1 ? "" : "s"} from the popular package "${nearest}". AI code generators commonly emit these when guessing package names.`,
            fix: `Verify "${name}" is the intended dependency. If you meant "${nearest}", replace it and rotate any credentials that were sent to machines where "${name}" ran (install scripts can exfiltrate env).`,
            data: { name, nearest, distance }
          });
        }
      }
    }

    return findings;
  }
};
