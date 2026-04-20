import { test } from "node:test";
import assert from "node:assert/strict";
import vc6, { levenshtein } from "../src/checks/vc6_hallucinated_package.js";
import { mkFile, mkIndex, fileLines } from "./helpers.js";

test("levenshtein basic cases", () => {
  assert.equal(levenshtein("kitten", "kitten"), 0);
  assert.equal(levenshtein("kitten", "sitten"), 1);
  assert.equal(levenshtein("kitten", "sittin"), 2);
  assert.equal(levenshtein("kitten", "sitting"), 3);
  assert.equal(levenshtein("", "abc"), 3);
  assert.equal(levenshtein("abc", ""), 3);
});

test("VC6 flags known typosquat 'react-supabase'", () => {
  const pkg = JSON.stringify({
    name: "x",
    dependencies: { "react-supabase": "1.0.0", "next": "14.0.0" }
  });
  const index = mkIndex([mkFile("package.json", pkg)]);
  const findings = vc6.run({ index, fileLines });
  assert.ok(findings.some((f) => f.title.includes("react-supabase")));
});

test("VC6 flags Levenshtein-2 distance to a top package (axios)", () => {
  const pkg = JSON.stringify({
    name: "x",
    dependencies: { "axiois": "1.0.0" }
  });
  const index = mkIndex([mkFile("package.json", pkg)]);
  const findings = vc6.run({ index, fileLines });
  assert.ok(findings.some((f) => /axiois/.test(f.title) && /axios/.test(f.title)));
});

test("VC6 does not flag real packages", () => {
  const pkg = JSON.stringify({
    name: "x",
    dependencies: { "next": "14.0.0", "react": "18.0.0", "zod": "3.0.0", "openai": "4.0.0", "@supabase/supabase-js": "2.0.0" }
  });
  const index = mkIndex([mkFile("package.json", pkg)]);
  const findings = vc6.run({ index, fileLines });
  assert.equal(findings.length, 0);
});

test("VC6 skips very short names", () => {
  const pkg = JSON.stringify({
    name: "x",
    dependencies: { "fs": "0.0.1", "ok": "1.0.0" }
  });
  const index = mkIndex([mkFile("package.json", pkg)]);
  const findings = vc6.run({ index, fileLines });
  assert.equal(findings.length, 0);
});
