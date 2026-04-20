# valtik-vibe-code-triage

Static scanner for "vibe-coded" Next.js + Supabase + Clerk apps built with
**Lovable, v0, Bolt, Replit Agent, Claude Artifacts, Cursor composer** and
similar AI code generators.

These tools produce working apps that ship with predictable security gaps
their makers don't audit away:

- **70%+ of Lovable apps** surveyed in 2025 shipped with Supabase Row-Level
  Security **disabled** on at least one table
- **24.7%** of AI-generated code carries exploitable security flaws (multiple
  academic + industry studies, 2024-2026)
- **March 2026** saw the `axios@1.14.1` AI-hallucinated-typosquat incident
- Common misconfigs: exposed service-role keys, Clerk `unsafeMetadata` used
  for role checks, missing `await auth()` on route handlers,
  `USING (true)` RLS policies

This tool looks for the ten specific anti-patterns those apps keep shipping
with.

## Install

```bash
npx valtik-vibe-code-triage <path>
```

or

```bash
npm i -g valtik-vibe-code-triage
vibe-code-triage <path>
```

## Usage

```
$ vibe-code-triage --help

Usage: vibe-code-triage <path> [options]

Arguments:
  path               Path to repo root (default: .)

Options:
  --checks <list>    Run only specific check IDs (e.g., VC1,VC3,VC7)
  --json             Machine-readable JSON output
  --sarif            SARIF 2.1.0 output for GitHub code scanning
  --fail-on <level>  Exit non-zero on severity >= level
  --ignore <glob>    Additional path to ignore (repeatable)
  --version          Print version and exit
  --help, -h         Show this help
```

## Check reference

| ID    | Title                                        | Severity         |
| ----- | -------------------------------------------- | ---------------- |
| VC1   | Supabase RLS disabled in migration SQL       | CRITICAL         |
| VC2   | Permissive RLS policy                        | HIGH             |
| VC3   | Service-role key exposed to client           | CRITICAL         |
| VC4   | Clerk `unsafeMetadata` used for auth         | HIGH             |
| VC5   | Next.js route handler missing auth           | HIGH / MEDIUM    |
| VC6   | AI-hallucinated / typosquat package          | HIGH / MEDIUM    |
| VC7   | Hardcoded secret in committed file           | CRITICAL         |
| VC8   | POST endpoint without CSRF protection        | MEDIUM           |
| VC9   | `.env` file committed                        | CRITICAL         |
| VC10  | Dangerous default CORS                       | MEDIUM           |

### VC1 — Supabase RLS disabled

Walks `supabase/migrations/*.sql` (and plain `migrations/*.sql`). For every
`CREATE TABLE`, verifies there's a corresponding
`ALTER TABLE <name> ENABLE ROW LEVEL SECURITY` somewhere in the migration
tree. Missing one = the anon key can read/write every row in that table.

**Fix:** `ALTER TABLE "<table>" ENABLE ROW LEVEL SECURITY;` plus a
`CREATE POLICY ... USING (owner_id = auth.uid())`.

### VC2 — Permissive RLS policy

Flags:
- `USING (true)` — allows everything
- `USING (auth.role() = 'authenticated')` alone — any logged-in user on any
  tenant can read every row
- Missing `USING` clause on `SELECT` / `UPDATE` / `DELETE` / `ALL` policies

### VC3 — Service-role key exposed to client

Catches `SUPABASE_SERVICE_ROLE_KEY` references from files under `app/`,
`pages/`, `components/`, or `src/` (excluding `api/` and `server/`).

Also always flags `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` — the
`NEXT_PUBLIC_` prefix forces the value into the client bundle.

### VC4 — Clerk `unsafeMetadata` used for auth

`unsafeMetadata` is client-writable by design. Any signed-in user can call
`user.update({ unsafeMetadata: { role: "admin" } })` and flip an
authorisation check they control. Use `publicMetadata` (server-writable,
client-readable) or `privateMetadata` (server-only) instead.

### VC5 — Next.js route handler missing auth

Walks `app/api/**/route.ts` and `pages/api/**`. If the handler writes
(`insert`/`update`/`delete`/`upsert`/`create`) and has no auth call
(`auth()`/`getAuth()`/`currentUser()`/`getSession()`/etc.) → **HIGH**.
If it's read-only but returns sensitive fields → **MEDIUM**. Webhook paths
are skipped.

### VC6 — AI-hallucinated / typosquat package

Parses `package.json` dependencies. Matches against a curated list of
known AI-hallucinated package names, plus Levenshtein distance ≤ 2 to
names in a curated popular-package list (`src/data/npm-top5000.json`).

### VC7 — Hardcoded secret

Grep for `sk_live_`, `sk_test_`, `ghp_`, `gho_`, `AKIA`, `AIza`, OpenAI
`sk-` keys, Anthropic `sk-ant-` keys, JWTs, SendGrid, Twilio, and other
common formats. Skips `.env*`, lock files, and obvious placeholder contexts.

### VC8 — Missing CSRF / open POST endpoint

For POST/PUT/PATCH/DELETE handlers that mutate state, looks for *any*
CSRF indicator: CSRF token, SameSite cookie, Turnstile/hCaptcha
verification, origin check, webhook signature, or an auth call.

### VC9 — `.env` file committed

Flags tracked `.env`, `.env.local`, `.env.production`, etc.
`.env.example` / `.env.template` / `.env.sample` are always allowed.

### VC10 — Dangerous default CORS

Flags `Access-Control-Allow-Origin: *` combined with credential-carrying
behavior, and `cors({ origin: true })` patterns that reflect arbitrary
origins.

## Target audience

- **Indie hackers** auditing their own Lovable / v0 / Bolt / Replit Agent
  exports before shipping to paying customers.
- **Bug bounty hunters** auditing new Lovable / Product Hunt / Hacker News
  launches. The `--json` and `--sarif` outputs plug into triage pipelines.
- **Security teams** enforcing a minimum bar on internal Next.js apps.

## CI

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with: { node-version: '20' }
- run: npx valtik-vibe-code-triage . --sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```

or fail the build:

```yaml
- run: npx valtik-vibe-code-triage . --fail-on high
```

## Limitations

- Regex-based static analysis — not an AST walker. Expect false positives
  on novel patterns and false negatives on obfuscation.
- Scans plain text only; skips minified JS.
- File reads capped at 2MB.
- Not a replacement for runtime black-box testing. Pair with
  [`valtik-rls-tester`](https://github.com/TreRB/rls-tester) for live tenant
  isolation proofs.

## Disclaimer

You must have authorization to scan any repository you don't own. This tool
reports possible anti-patterns; confirm impact manually before filing bug
reports or bounty submissions.

## License

MIT © 2026 Valtik Studios LLC
