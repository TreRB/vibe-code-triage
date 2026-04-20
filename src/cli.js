#!/usr/bin/env node
// valtik-vibe-code-triage — static scanner for AI-generated Next.js +
// Supabase + Clerk apps (Lovable, v0, Bolt, Replit Agent, Claude Artifacts,
// Cursor composer, ...).

import chalk from "chalk";
import { scanRepo } from "./scan.js";
import { CHECKS } from "./checks/index.js";
import { renderHuman, renderJSON, renderSARIF, shouldFail } from "./report.js";

const VERSION = "0.1.0";

const HELP_TEXT = `Usage: vibe-code-triage <path> [options]

Static scanner for AI-generated (Lovable / Bolt / v0 / Replit Agent /
Claude Artifacts / Cursor composer / similar) Next.js + Supabase +
Clerk apps. Detects 10 common anti-patterns that ship by default.

Arguments:
  path               Path to repo root (default: .)

Options:
  --checks <list>    Run only specific check IDs (e.g., VC1,VC3,VC7)
  --json             Machine-readable JSON output
  --sarif            SARIF 2.1.0 output for GitHub code scanning
  --fail-on <level>  Exit non-zero on severity >= level
                     (info|low|medium|high|critical)
  --ignore <glob>    Additional path to ignore (repeatable)
  --version          Print version and exit
  --help, -h         Show this help

Checks:
  VC1   Supabase RLS disabled in migration SQL         CRITICAL
  VC2   Permissive RLS policy (USING (true) / any-user) HIGH
  VC3   Service-role key exposed to client             CRITICAL
  VC4   Clerk unsafeMetadata used for auth decisions   HIGH
  VC5   Next.js route handler missing auth             HIGH / MEDIUM
  VC6   AI-hallucinated / typosquat package            HIGH / MEDIUM
  VC7   Hardcoded secret in committed file             CRITICAL
  VC8   POST endpoint without CSRF protection          MEDIUM
  VC9   .env file committed                            CRITICAL
  VC10  Dangerous default CORS                         MEDIUM

Examples:
  $ npx valtik-vibe-code-triage ./my-lovable-app
  $ npx valtik-vibe-code-triage ./repo --checks VC1,VC3 --json
  $ npx valtik-vibe-code-triage ./repo --sarif > results.sarif
  $ npx valtik-vibe-code-triage ./repo --fail-on high
`;

export function parseArgs(argv) {
  const opts = {
    root: ".",
    checks: null,
    json: false,
    sarif: false,
    failOn: null,
    ignore: [],
    help: false,
    version: false
  };
  const args = argv.slice();
  while (args.length) {
    const a = args.shift();
    switch (a) {
      case "--help":
      case "-h":
        opts.help = true;
        break;
      case "--version":
      case "-v":
        opts.version = true;
        break;
      case "--checks": {
        const v = args.shift() || "";
        opts.checks = v.split(",").map((s) => s.trim()).filter(Boolean);
        break;
      }
      case "--json":
        opts.json = true;
        break;
      case "--sarif":
        opts.sarif = true;
        break;
      case "--fail-on":
        opts.failOn = args.shift();
        break;
      case "--ignore":
        opts.ignore.push(args.shift());
        break;
      default:
        if (!a.startsWith("-")) {
          // First positional arg is path. Ignore any extra.
          if (opts.root === ".") opts.root = a;
          else throw new Error(`unknown extra argument: ${a}`);
        } else {
          throw new Error(`unknown argument: ${a}`);
        }
    }
  }
  return opts;
}

export async function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    process.stderr.write(chalk.red(`Error: ${err.message}\n\n`));
    process.stderr.write(HELP_TEXT);
    return 2;
  }
  if (opts.help) {
    process.stdout.write(HELP_TEXT);
    return 0;
  }
  if (opts.version) {
    process.stdout.write(`valtik-vibe-code-triage ${VERSION}\n`);
    return 0;
  }

  // Validate --checks IDs.
  if (opts.checks) {
    const valid = new Set(CHECKS.map((c) => c.id));
    const bad = opts.checks.filter((c) => !valid.has(c));
    if (bad.length) {
      process.stderr.write(chalk.red(`Error: unknown check id(s): ${bad.join(", ")}. Valid: ${[...valid].join(", ")}\n`));
      return 2;
    }
  }

  const result = await scanRepo({
    root: opts.root,
    checks: opts.checks,
    ignore: opts.ignore
  });

  // Add meta so JSON/SARIF consumers have versioning.
  result.meta = {
    tool: "valtik-vibe-code-triage",
    version: VERSION,
    timestamp: new Date().toISOString()
  };

  if (opts.sarif) {
    process.stdout.write(renderSARIF(result) + "\n");
  } else if (opts.json) {
    process.stdout.write(renderJSON(result) + "\n");
  } else {
    process.stdout.write(renderHuman(result));
  }

  if (opts.failOn && shouldFail(result.findings, opts.failOn)) {
    return 1;
  }
  return 0;
}

const isMain = import.meta.url === `file://${process.argv[1]}` ||
  (process.argv[1] && process.argv[1].endsWith("cli.js"));
if (isMain) {
  main(process.argv.slice(2)).then((code) => {
    process.exit(code);
  }).catch((err) => {
    process.stderr.write(chalk.red(`Fatal: ${err?.stack || err}\n`));
    process.exit(2);
  });
}
