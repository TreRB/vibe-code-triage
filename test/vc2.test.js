import { test } from "node:test";
import assert from "node:assert/strict";
import vc2 from "../src/checks/vc2_permissive_rls.js";
import { mkFile, mkIndex, fileLines } from "./helpers.js";

test("VC2 flags USING (true)", () => {
  const sql = `
create policy "everyone reads" on public.posts
  for select using (true);
`;
  const index = mkIndex([mkFile("supabase/migrations/0001.sql", sql)]);
  const findings = vc2.run({ index, fileLines });
  assert.equal(findings.length, 1);
  assert.match(findings[0].title, /USING \(true\)/);
});

test("VC2 flags auth.role() = authenticated alone", () => {
  const sql = `
create policy "authed can read" on public.profiles
  for select using (auth.role() = 'authenticated');
`;
  const index = mkIndex([mkFile("supabase/migrations/0001.sql", sql)]);
  const findings = vc2.run({ index, fileLines });
  assert.equal(findings.length, 1);
  assert.match(findings[0].title, /authenticated/);
});

test("VC2 does not flag auth.role() combined with ownership", () => {
  const sql = `
create policy "own rows only" on public.profiles
  for select using (auth.role() = 'authenticated' and owner_id = auth.uid());
`;
  const index = mkIndex([mkFile("supabase/migrations/0001.sql", sql)]);
  const findings = vc2.run({ index, fileLines });
  assert.equal(findings.length, 0);
});

test("VC2 does not flag healthy USING (owner_id = auth.uid())", () => {
  const sql = `
create policy "own rows only" on public.profiles
  for select using (owner_id = auth.uid());
`;
  const index = mkIndex([mkFile("supabase/migrations/0001.sql", sql)]);
  const findings = vc2.run({ index, fileLines });
  assert.equal(findings.length, 0);
});
