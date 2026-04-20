import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanRepo } from "../src/scan.js";
import { parseArgs, main } from "../src/cli.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SAFE = path.join(__dirname, "fixtures/safe");

// Materialize vulnerable fixture at test-runtime. The committed repo holds
// NO literal real-shape secrets (GitHub Push Protection would reject). The
// strings generated below still match each VC7 regex so the scanner fires.
function materializeVulnerableFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-vuln-"));
  fs.cpSync(path.join(__dirname, "fixtures/vulnerable"), root, { recursive: true });
  const STRIPE = "sk" + "_" + "live_" + "ValtikFixtureDoNotUseForRealBilling00";
  const CLERK_SK = "sk" + "_" + "live_" + "ValtikClerkFixtureDoNotUseAnywhere00";
  const SUPA_JWT = "eyJ" + "fakeValtikFixtureForCodeTriageONLY1234567890";
  const GH_PAT = "gh" + "p_" + "ValtikFixturePATOnlyNotARealToken123456";
  const AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE";
  const OPENAI_KEY = "sk-proj_" + "ValtikOpenAIFixtureNotReal0000000";
  fs.writeFileSync(path.join(root, ".env.local"),
    `NEXT_PUBLIC_SUPABASE_URL=https://abcdef.supabase.co\n` +
    `STRIPE_SECRET_KEY=${STRIPE}\n` +
    `CLERK_SECRET_KEY=${CLERK_SK}\n` +
    `SUPABASE_SERVICE_ROLE_KEY=${SUPA_JWT}\n`);
  fs.mkdirSync(path.join(root, "src/lib"), { recursive: true });
  fs.writeFileSync(path.join(root, "src/lib/config.ts"),
    `export const STRIPE_KEY = ${JSON.stringify(STRIPE)};\n` +
    `export const GITHUB_TOKEN = ${JSON.stringify(GH_PAT)};\n` +
    `export const OPENAI_KEY = ${JSON.stringify(OPENAI_KEY)};\n` +
    `export const AWS_KEY = ${JSON.stringify(AWS_KEY)};\n` +
    `export const CORS_HEADERS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true" };\n`);
  return root;
}

const VULN = materializeVulnerableFixture();

test("parseArgs parses flags", () => {
  const opts = parseArgs(["./x", "--checks", "VC1,VC3", "--json", "--fail-on", "high", "--ignore", "foo"]);
  assert.equal(opts.root, "./x");
  assert.deepEqual(opts.checks, ["VC1", "VC3"]);
  assert.equal(opts.json, true);
  assert.equal(opts.failOn, "high");
  assert.deepEqual(opts.ignore, ["foo"]);
});

test("parseArgs rejects unknown flag", () => {
  assert.throws(() => parseArgs(["--bogus"]));
});

test("parseArgs allows --help", () => {
  const opts = parseArgs(["--help"]);
  assert.equal(opts.help, true);
});

test("scanRepo finds expected findings in vulnerable fixture", async () => {
  const result = await scanRepo({ root: VULN });
  const byCheck = {};
  for (const f of result.findings) {
    byCheck[f.checkId] = (byCheck[f.checkId] || 0) + 1;
  }
  // Every check should fire at least once somewhere in the vulnerable tree.
  for (const id of ["VC1", "VC2", "VC3", "VC4", "VC5", "VC6", "VC7", "VC8", "VC9", "VC10"]) {
    assert.ok(byCheck[id] >= 1, `expected VC${id.slice(2)} to fire in vulnerable fixture, got ${JSON.stringify(byCheck)}`);
  }
});

test("scanRepo finds NO findings in safe fixture", async () => {
  const result = await scanRepo({ root: SAFE });
  if (result.findings.length > 0) {
    const detail = result.findings.map((f) => `${f.checkId} ${f.file}:${f.line} ${f.title}`).join("\n  ");
    assert.fail(`safe fixture should produce zero findings but got:\n  ${detail}`);
  }
});

test("scanRepo respects --checks filter", async () => {
  const result = await scanRepo({ root: VULN, checks: ["VC9"] });
  assert.ok(result.findings.every((f) => f.checkId === "VC9"));
  assert.ok(result.findings.length >= 1);
});

test("main returns 1 when --fail-on triggers", async () => {
  const origStdout = process.stdout.write;
  process.stdout.write = () => true;
  try {
    const code = await main([VULN, "--fail-on", "critical", "--json"]);
    assert.equal(code, 1);
  } finally {
    process.stdout.write = origStdout;
  }
});

test("main returns 0 for safe tree with --fail-on low", async () => {
  const origStdout = process.stdout.write;
  process.stdout.write = () => true;
  try {
    const code = await main([SAFE, "--fail-on", "low"]);
    assert.equal(code, 0);
  } finally {
    process.stdout.write = origStdout;
  }
});

test("main --help returns 0", async () => {
  const origStdout = process.stdout.write;
  process.stdout.write = () => true;
  try {
    const code = await main(["--help"]);
    assert.equal(code, 0);
  } finally {
    process.stdout.write = origStdout;
  }
});

test("scan completes in under 5 seconds on the vulnerable fixture", async () => {
  const t0 = Date.now();
  await scanRepo({ root: VULN });
  const ms = Date.now() - t0;
  assert.ok(ms < 5000, `expected <5s, got ${ms}ms`);
});
