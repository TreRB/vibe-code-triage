import { test } from "node:test";
import assert from "node:assert/strict";
import vc1 from "../src/checks/vc1_rls_disabled.js";
import { mkFile, mkIndex, fileLines } from "./helpers.js";

test("VC1 flags CREATE TABLE without ENABLE RLS", () => {
  const sql = `
create table public.profiles (id uuid primary key);
-- no alter-enable-rls here
create table public.posts (id uuid primary key);
alter table public.posts enable row level security;
`;
  const index = mkIndex([mkFile("supabase/migrations/0001_init.sql", sql)]);
  const findings = vc1.run({ index, fileLines });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "critical");
  assert.match(findings[0].title, /profiles/);
});

test("VC1 matches ENABLE RLS across separate migration files", () => {
  const a = `create table public.users (id uuid primary key);`;
  const b = `alter table public.users enable row level security;`;
  const index = mkIndex([
    mkFile("supabase/migrations/0001_a.sql", a),
    mkFile("supabase/migrations/0002_b.sql", b)
  ]);
  const findings = vc1.run({ index, fileLines });
  assert.equal(findings.length, 0);
});

test("VC1 handles case-insensitive and quoted identifiers", () => {
  const sql = `CREATE TABLE IF NOT EXISTS "public"."Orders" (id uuid);`;
  const index = mkIndex([mkFile("migrations/001.sql", sql)]);
  const findings = vc1.run({ index, fileLines });
  assert.equal(findings.length, 1);
  assert.match(findings[0].evidence, /orders/i);
});

test("VC1 ignores non-migration files", () => {
  const sql = `create table foo (id uuid);`;
  const index = mkIndex([mkFile("src/lib/schema.sql", sql)]);
  const findings = vc1.run({ index, fileLines });
  assert.equal(findings.length, 0);
});
