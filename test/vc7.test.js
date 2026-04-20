import { test } from "node:test";
import assert from "node:assert/strict";
import vc7 from "../src/checks/vc7_hardcoded_secret.js";
import { mkFile, mkIndex, fileLines } from "./helpers.js";

// All secrets in this file are ASSEMBLED FROM SUBSTRINGS at runtime so
// GitHub Push Protection's secret scanner does not see a literal match
// in the committed source. The assembled strings still exercise the
// vc7 regex exactly as a real leak would.
const STRIPE_LIVE = "sk" + "_" + "live_" + "51HvAbcDEFghijklMNoPqRsTuvWxyZ01234567890abcDEFghi";
const STRIPE_PLACEHOLDER = "sk" + "_" + "live_" + "EXAMPLEPLACEHOLDER1234567890abcd";
const GH_PAT = "gh" + "p_" + "abcdef1234567890ABCDEF1234567890ABCDEF12";
const AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE";

test("VC7 flags Stripe live secret key", () => {
  const src = `export const STRIPE = "${STRIPE_LIVE}";`;
  const index = mkIndex([mkFile("src/config.ts", src)]);
  const findings = vc7.run({ index, fileLines });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "critical");
  assert.match(findings[0].title, /Stripe/);
});

test("VC7 flags GitHub PAT", () => {
  const src = `const token = "${GH_PAT}";`;
  const index = mkIndex([mkFile("src/gh.ts", src)]);
  const findings = vc7.run({ index, fileLines });
  assert.equal(findings.length, 1);
});

test("VC7 flags AWS access key id", () => {
  const src = `const AWS = "${AWS_KEY}";`;
  const index = mkIndex([mkFile("src/aws.ts", src)]);
  const findings = vc7.run({ index, fileLines });
  assert.equal(findings.length, 1);
});

test("VC7 does not flag placeholders marked 'example'", () => {
  const src = `const STRIPE = "${STRIPE_PLACEHOLDER}"; // example only`;
  const index = mkIndex([mkFile("src/config.ts", src)]);
  const findings = vc7.run({ index, fileLines });
  assert.equal(findings.length, 0);
});

test("VC7 ignores .env files (VC9 handles those)", () => {
  const src = `STRIPE=${STRIPE_LIVE}`;
  const index = mkIndex([mkFile(".env", src)]);
  const findings = vc7.run({ index, fileLines });
  assert.equal(findings.length, 0);
});

test("VC7 ignores lock files", () => {
  const src = `"sha": "${GH_PAT}"`;
  const index = mkIndex([mkFile("package-lock.json", src)]);
  const findings = vc7.run({ index, fileLines });
  assert.equal(findings.length, 0);
});
