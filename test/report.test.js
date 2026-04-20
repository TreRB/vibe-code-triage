import { test } from "node:test";
import assert from "node:assert/strict";
import { renderJSON, renderSARIF, renderHuman, shouldFail, severityRank } from "../src/report.js";

const FAKE = {
  root: "/x",
  fileCount: 3,
  checks: [{ id: "VC1", title: "t", duration: 1 }],
  findings: [
    { checkId: "VC1", severity: "critical", file: "a.sql", line: 1, title: "x", evidence: "e", fix: "f" },
    { checkId: "VC2", severity: "medium", file: "b.sql", line: 2, title: "y", evidence: "e2", fix: "f2" }
  ]
};

test("severityRank returns sensible numbers", () => {
  assert.ok(severityRank("critical") > severityRank("high"));
  assert.ok(severityRank("high") > severityRank("medium"));
  assert.ok(severityRank("medium") > severityRank("low"));
});

test("shouldFail threshold works", () => {
  assert.equal(shouldFail(FAKE.findings, "critical"), true);
  assert.equal(shouldFail(FAKE.findings, "high"), true);
  assert.equal(shouldFail(FAKE.findings, "medium"), true);
  assert.equal(shouldFail([FAKE.findings[1]], "high"), false);
});

test("renderJSON is valid JSON", () => {
  const out = renderJSON(FAKE);
  const parsed = JSON.parse(out);
  assert.equal(parsed.findings.length, 2);
});

test("renderSARIF emits 2.1.0 shape", () => {
  const out = renderSARIF(FAKE);
  const parsed = JSON.parse(out);
  assert.equal(parsed.version, "2.1.0");
  assert.equal(parsed.runs.length, 1);
  assert.equal(parsed.runs[0].tool.driver.name, "valtik-vibe-code-triage");
  assert.equal(parsed.runs[0].results.length, 2);
  assert.equal(parsed.runs[0].results[0].ruleId, "VC1");
  assert.equal(parsed.runs[0].results[0].level, "error");
  assert.equal(parsed.runs[0].results[1].level, "warning");
});

test("renderHuman produces non-empty text", () => {
  const out = renderHuman(FAKE);
  assert.ok(out.length > 100);
  assert.match(out, /VIBE-CODE-TRIAGE/);
  assert.match(out, /VC1/);
});
