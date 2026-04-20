// scan.js — file walker + check dispatcher.
//
// Walks a repo rooted at opts.root, reading files up to MAX_FILE_BYTES,
// skipping node_modules / .git / build outputs / the tool's own fixtures,
// then invokes each enabled check with a shared FileIndex.

import fs from "node:fs";
import path from "node:path";
import { CHECKS } from "./checks/index.js";

export const MAX_FILE_BYTES = 2 * 1024 * 1024; // 2MB hard cap per file

const DEFAULT_IGNORE = [
  "node_modules",
  ".git",
  ".next",
  ".turbo",
  "dist",
  "build",
  "out",
  "coverage",
  ".vercel",
  ".svelte-kit",
  ".cache"
];

const TEXT_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".sql", ".json", ".md", ".mdx",
  ".env", ".local", ".yaml", ".yml", ".toml",
  ".html", ".css",
  ""
]);

// Some files have no extension but are interesting (Dockerfile, .env).
function isTextCandidate(filename) {
  const ext = path.extname(filename).toLowerCase();
  if (TEXT_EXTENSIONS.has(ext)) return true;
  if (filename.startsWith(".env")) return true;
  if (filename === "Dockerfile") return true;
  return false;
}

function matchesIgnore(relPath, extraGlobs) {
  // simple glob-ish matcher: segments or substrings.
  for (const seg of DEFAULT_IGNORE) {
    if (relPath === seg || relPath.startsWith(seg + "/") || relPath.includes("/" + seg + "/")) {
      return true;
    }
  }
  for (const pat of extraGlobs || []) {
    if (!pat) continue;
    // Handle simple wildcard: * anywhere.
    if (pat.includes("*")) {
      const re = new RegExp("^" + pat.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$");
      if (re.test(relPath)) return true;
    } else if (relPath === pat || relPath.startsWith(pat + "/") || relPath.includes("/" + pat + "/")) {
      return true;
    }
  }
  return false;
}

/**
 * Build a file index for the given root directory.
 * Returns { root, files: [{ path, relPath, size, content, lines }] }.
 * content is null if the file is > MAX_FILE_BYTES (oversized).
 */
export function buildFileIndex(root, { ignore = [] } = {}) {
  const absRoot = path.resolve(root);
  const files = [];
  const stack = [absRoot];

  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const abs = path.join(dir, entry.name);
      const rel = path.relative(absRoot, abs).split(path.sep).join("/");
      if (matchesIgnore(rel, ignore)) continue;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        stack.push(abs);
        continue;
      }
      if (!entry.isFile()) continue;

      let stat;
      try {
        stat = fs.statSync(abs);
      } catch {
        continue;
      }

      const entryFile = {
        path: abs,
        relPath: rel,
        size: stat.size,
        content: null,
        lines: null,
        oversized: stat.size > MAX_FILE_BYTES,
        textual: isTextCandidate(entry.name)
      };

      if (entryFile.textual && !entryFile.oversized) {
        try {
          entryFile.content = fs.readFileSync(abs, "utf8");
        } catch {
          entryFile.content = null;
        }
      }

      files.push(entryFile);
    }
  }

  return { root: absRoot, files };
}

/**
 * Return file.content split into lines (cached lazy-ish).
 */
export function fileLines(file) {
  if (file.lines) return file.lines;
  if (file.content == null) return [];
  file.lines = file.content.split(/\r?\n/);
  return file.lines;
}

/**
 * Scan a repo root by running each enabled check.
 * opts: { root, checks?: string[], ignore?: string[] }
 * Returns { root, findings, checks: [{ id, duration, error? }], fileCount }.
 */
export async function scanRepo(opts) {
  const { root } = opts;
  const index = buildFileIndex(root, { ignore: opts.ignore || [] });
  const enabled = new Set((opts.checks && opts.checks.length) ? opts.checks : CHECKS.map((c) => c.id));

  const findings = [];
  const checkResults = [];

  for (const check of CHECKS) {
    if (!enabled.has(check.id)) continue;
    const start = Date.now();
    try {
      const out = await check.run({ index, fileLines, opts });
      if (Array.isArray(out)) {
        for (const f of out) {
          findings.push({ checkId: check.id, ...f });
        }
      }
      checkResults.push({ id: check.id, title: check.title, duration: Date.now() - start });
    } catch (err) {
      checkResults.push({
        id: check.id,
        title: check.title,
        duration: Date.now() - start,
        error: String(err && err.stack || err)
      });
    }
  }

  return {
    root: index.root,
    findings,
    checks: checkResults,
    fileCount: index.files.length
  };
}
