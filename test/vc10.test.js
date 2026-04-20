import { test } from "node:test";
import assert from "node:assert/strict";
import vc10 from "../src/checks/vc10_cors.js";
import { mkFile, mkIndex, fileLines } from "./helpers.js";

test("VC10 flags * origin + Allow-Credentials: true", () => {
  const src = `
    export const CORS = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials": "true"
    };
  `;
  const index = mkIndex([mkFile("src/cors.ts", src)]);
  const findings = vc10.run({ index, fileLines });
  assert.equal(findings.length, 1);
});

test("VC10 flags cors({ origin: true })", () => {
  const src = `import cors from "cors"; app.use(cors({ origin: true, credentials: true }));`;
  const index = mkIndex([mkFile("src/app.ts", src)]);
  const findings = vc10.run({ index, fileLines });
  assert.equal(findings.length, 1);
});

test("VC10 flags * + credentials: 'include' fetch", () => {
  const src = `
    res.setHeader("Access-Control-Allow-Origin", "*");
    fetch("/api/data", { credentials: "include" });
  `;
  const index = mkIndex([mkFile("src/api.ts", src)]);
  const findings = vc10.run({ index, fileLines });
  assert.equal(findings.length, 1);
});

test("VC10 does not flag an allowlisted origin", () => {
  const src = `
    const ALLOW = ["https://example.com"];
    if (ALLOW.includes(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
  `;
  const index = mkIndex([mkFile("src/cors.ts", src)]);
  const findings = vc10.run({ index, fileLines });
  assert.equal(findings.length, 0);
});
