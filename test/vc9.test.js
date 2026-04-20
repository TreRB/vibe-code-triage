import { test } from "node:test";
import assert from "node:assert/strict";
import vc9 from "../src/checks/vc9_env_committed.js";
import { mkFile, mkIndex, fileLines } from "./helpers.js";

test("VC9 flags a committed .env.local", () => {
  const content = "SUPABASE_SERVICE_ROLE_KEY=eyJsecret\nSTRIPE_SECRET_KEY=sk_live_abc\n";
  const index = mkIndex([mkFile(".env.local", content)]);
  const findings = vc9.run({ index, fileLines });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "critical");
  assert.match(findings[0].evidence, /SUPABASE_SERVICE_ROLE_KEY/);
});

test("VC9 flags .env at repo root", () => {
  const index = mkIndex([mkFile(".env", "KEY=value\n")]);
  const findings = vc9.run({ index, fileLines });
  assert.equal(findings.length, 1);
});

test("VC9 does NOT flag .env.example", () => {
  const index = mkIndex([mkFile(".env.example", "SUPABASE_URL=https://example\n")]);
  const findings = vc9.run({ index, fileLines });
  assert.equal(findings.length, 0);
});

test("VC9 does NOT flag .env.template or .env.sample", () => {
  const index = mkIndex([
    mkFile(".env.template", "KEY=\n"),
    mkFile(".env.sample", "KEY=\n")
  ]);
  const findings = vc9.run({ index, fileLines });
  assert.equal(findings.length, 0);
});
