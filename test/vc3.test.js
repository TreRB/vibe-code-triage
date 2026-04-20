import { test } from "node:test";
import assert from "node:assert/strict";
import vc3 from "../src/checks/vc3_service_role_client.js";
import { mkFile, mkIndex, fileLines } from "./helpers.js";

test("VC3 flags SUPABASE_SERVICE_ROLE_KEY in a client component", () => {
  const src = `
    import { createClient } from "@supabase/supabase-js";
    export const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);
  `;
  const index = mkIndex([mkFile("components/Admin.tsx", src)]);
  const findings = vc3.run({ index, fileLines });
  assert.ok(findings.length >= 1);
  assert.equal(findings[0].severity, "critical");
});

test("VC3 does NOT flag SUPABASE_SERVICE_ROLE_KEY under app/api/", () => {
  const src = `
    export async function POST() {
      const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
      return Response.json({ ok: true });
    }
  `;
  const index = mkIndex([mkFile("app/api/admin/route.ts", src)]);
  const findings = vc3.run({ index, fileLines });
  assert.equal(findings.length, 0);
});

test("VC3 always flags NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY (even in server paths)", () => {
  const src = `
    const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;
  `;
  const index = mkIndex([mkFile("app/api/admin/route.ts", src)]);
  const findings = vc3.run({ index, fileLines });
  assert.equal(findings.length, 1);
  assert.match(findings[0].title, /NEXT_PUBLIC_/);
});

test("VC3 does not flag a server/ module", () => {
  const src = `
    export const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  `;
  const index = mkIndex([mkFile("src/server/admin.ts", src)]);
  const findings = vc3.run({ index, fileLines });
  assert.equal(findings.length, 0);
});
