import { test } from "node:test";
import assert from "node:assert/strict";
import vc4 from "../src/checks/vc4_clerk_unsafe_metadata.js";
import { mkFile, mkIndex, fileLines } from "./helpers.js";

test("VC4 flags unsafeMetadata.role in an if condition", () => {
  const src = `
    if (user.unsafeMetadata.role === "admin") {
      grantAdminAccess();
    }
  `;
  const index = mkIndex([mkFile("app/page.tsx", src)]);
  const findings = vc4.run({ index, fileLines });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
});

test("VC4 flags optional-chain unsafeMetadata.isAdmin", () => {
  const src = `
    const canEdit = user?.unsafeMetadata?.isAdmin ?? false;
  `;
  const index = mkIndex([mkFile("app/page.tsx", src)]);
  const findings = vc4.run({ index, fileLines });
  assert.equal(findings.length, 1);
});

test("VC4 does not flag publicMetadata", () => {
  const src = `
    if (user.publicMetadata.role === "admin") {
      grantAdminAccess();
    }
  `;
  const index = mkIndex([mkFile("app/page.tsx", src)]);
  const findings = vc4.run({ index, fileLines });
  assert.equal(findings.length, 0);
});

test("VC4 skips non-conditional, non-role accesses", () => {
  // Display-only usage with no role-ish property name and no conditional.
  const src = `
    const pref = user.unsafeMetadata.theme;
    console.log(pref);
  `;
  const index = mkIndex([mkFile("components/Nav.tsx", src)]);
  const findings = vc4.run({ index, fileLines });
  assert.equal(findings.length, 0);
});
