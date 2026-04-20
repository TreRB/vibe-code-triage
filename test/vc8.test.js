import { test } from "node:test";
import assert from "node:assert/strict";
import vc8 from "../src/checks/vc8_open_post.js";
import { mkFile, mkIndex, fileLines } from "./helpers.js";

test("VC8 flags POST handler with no CSRF indicator", () => {
  const src = `
    export async function POST(req) {
      const body = await req.json();
      await db.insert(body);
      return Response.json({ ok: true });
    }
  `;
  const index = mkIndex([mkFile("app/api/things/route.ts", src)]);
  const findings = vc8.run({ index, fileLines });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "medium");
});

test("VC8 is satisfied by auth()", () => {
  const src = `
    import { auth } from "@clerk/nextjs/server";
    export async function POST(req) {
      const { userId } = await auth();
      if (!userId) return new Response("no", { status: 401 });
      await db.insert(await req.json());
      return Response.json({ ok: true });
    }
  `;
  const index = mkIndex([mkFile("app/api/things/route.ts", src)]);
  const findings = vc8.run({ index, fileLines });
  assert.equal(findings.length, 0);
});

test("VC8 is satisfied by Turnstile verification", () => {
  const src = `
    export async function POST(req) {
      const token = req.headers.get("cf-turnstile-response");
      const ok = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: token });
      if (!ok) return new Response("nope", { status: 400 });
      await db.insert(await req.json());
      return Response.json({ ok: true });
    }
  `;
  const index = mkIndex([mkFile("app/api/things/route.ts", src)]);
  const findings = vc8.run({ index, fileLines });
  assert.equal(findings.length, 0);
});

test("VC8 skips webhooks", () => {
  const src = `
    export async function POST(req) {
      await db.insert(await req.json());
      return Response.json({ ok: true });
    }
  `;
  const index = mkIndex([mkFile("app/api/webhooks/stripe/route.ts", src)]);
  const findings = vc8.run({ index, fileLines });
  assert.equal(findings.length, 0);
});

test("VC8 does not flag non-mutating POST endpoint", () => {
  const src = `
    export async function POST(req) {
      const { text } = await req.json();
      return Response.json({ length: text.length });
    }
  `;
  const index = mkIndex([mkFile("app/api/echo/route.ts", src)]);
  const findings = vc8.run({ index, fileLines });
  assert.equal(findings.length, 0);
});
