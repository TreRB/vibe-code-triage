import { test } from "node:test";
import assert from "node:assert/strict";
import vc5 from "../src/checks/vc5_route_missing_auth.js";
import { mkFile, mkIndex, fileLines } from "./helpers.js";

test("VC5 flags POST handler that writes without auth", () => {
  const src = `
    import { createClient } from "@supabase/supabase-js";
    const supabase = createClient(url, key);
    export async function POST(req) {
      const body = await req.json();
      return Response.json(await supabase.from("posts").insert(body));
    }
  `;
  const index = mkIndex([mkFile("app/api/posts/route.ts", src)]);
  const findings = vc5.run({ index, fileLines });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
});

test("VC5 does not flag POST handler with Clerk auth()", () => {
  const src = `
    import { auth } from "@clerk/nextjs/server";
    import { createClient } from "@supabase/supabase-js";
    const supabase = createClient(url, key);
    export async function POST(req) {
      const { userId } = await auth();
      if (!userId) return new Response("unauthorized", { status: 401 });
      const body = await req.json();
      return Response.json(await supabase.from("posts").insert(body));
    }
  `;
  const index = mkIndex([mkFile("app/api/posts/route.ts", src)]);
  const findings = vc5.run({ index, fileLines });
  assert.equal(findings.length, 0);
});

test("VC5 flags MEDIUM on GET that returns sensitive fields without auth", () => {
  const src = `
    import { createClient } from "@supabase/supabase-js";
    const supabase = createClient(url, key);
    export async function GET() {
      const { data } = await supabase.from("user").select("id,email,subscription,admin");
      return Response.json({ users: data });
    }
  `;
  const index = mkIndex([mkFile("app/api/users/route.ts", src)]);
  const findings = vc5.run({ index, fileLines });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "medium");
});

test("VC5 ignores webhook paths", () => {
  const src = `
    export async function POST(req) {
      const body = await req.text();
      await db.insert(body);
      return Response.json({ ok: true });
    }
  `;
  const index = mkIndex([mkFile("app/api/webhooks/stripe/route.ts", src)]);
  const findings = vc5.run({ index, fileLines });
  assert.equal(findings.length, 0);
});

test("VC5 handles pages/api handler pattern", () => {
  const src = `
    export default async function handler(req, res) {
      if (req.method === "POST") {
        await db.insert(req.body);
        return res.status(200).end();
      }
      res.status(405).end();
    }
  `;
  const index = mkIndex([mkFile("pages/api/things.ts", src)]);
  const findings = vc5.run({ index, fileLines });
  assert.ok(findings.length >= 1);
});
