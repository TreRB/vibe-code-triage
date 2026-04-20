# vibe-code-triage

**Static scanner for AI-generated Next.js + Supabase + Clerk apps. Catches the ten security gaps that Lovable, v0, Bolt, Replit Agent, Claude Artifacts, and Cursor composer keep shipping.**

- **70% of Lovable apps** surveyed in 2025 shipped with Supabase Row Level Security **disabled** on at least one table.
- **24.7%** of AI-generated code carries exploitable security flaws (multiple academic and industry studies, 2024 to 2026).
- **March 2026**: the first AI-hallucinated typosquat incident (`axios@1.14.1`) hit production supply chains.

If you shipped something built by an AI code generator and you have paying users, run this tool first.

## Install and run

```bash
npx valtik-vibe-code-triage .
```

That's it. Node 20+. Zero runtime deps.

## What it catches

```
$ npx valtik-vibe-code-triage ./my-lovable-app

VIBE CODE TRIAGE  target: ./my-lovable-app

Parsed: 47 files (38 ts, 3 sql, 1 json, 5 other)

  [CRITICAL]  VC1  Table "documents" has no RLS enabled
              supabase/migrations/20260210_init.sql:42

  [CRITICAL]  VC3  SUPABASE_SERVICE_ROLE_KEY imported in client component
              src/components/DocumentList.tsx:8

  [HIGH]      VC4  Clerk unsafeMetadata used for role check
              src/lib/auth.ts:17  if (user.unsafeMetadata.role === 'admin')

  [HIGH]      VC5  Route handler /api/documents mutates without auth
              src/app/api/documents/route.ts:12  POST handler, no auth() call

  [HIGH]      VC6  "axios@1.14.1" matches known AI-hallucinated package name
              package.json:14  (real axios latest is 1.7.9)

Summary
  5 findings (2 critical, 3 high)

Exit: 1
```

## The ten checks

| ID    | Severity         | What fires                                                           |
| ----- | ---------------- | -------------------------------------------------------------------- |
| VC1   | CRITICAL         | Supabase RLS disabled (CREATE TABLE without ENABLE ROW LEVEL SECURITY) |
| VC2   | HIGH             | Permissive RLS policy (`USING (true)`, etc.)                          |
| VC3   | CRITICAL         | Service-role key imported into a client-side file                     |
| VC4   | HIGH             | Clerk `unsafeMetadata` used for authorization                         |
| VC5   | HIGH / MEDIUM    | Next.js route handler with state mutation and no auth() call          |
| VC6   | HIGH / MEDIUM    | AI-hallucinated or typosquat package name                             |
| VC7   | CRITICAL         | Hardcoded secret (Stripe, GitHub PAT, AWS key, OpenAI key, etc.)      |
| VC8   | MEDIUM           | POST / PUT / DELETE handler with no CSRF indicator                    |
| VC9   | CRITICAL         | `.env` / `.env.local` file committed to the repo                      |
| VC10  | MEDIUM           | Dangerous CORS (`*` with credentials, or reflect-origin)              |

Each finding includes a one-line fix. Full SARIF 2.1.0 output for GitHub code scanning.

## Why this exists

AquilaX, VibeAppScanner, and Snyk each cover part of this. All three are SaaS, require signup, and don't ship as a CLI you can pipe into CI. Checkmarx has written advice for AI-generated code but hasn't shipped tooling.

This is a CLI you can run on your laptop in under a second. No account, no rate limits, zero telemetry. Everything runs locally. 60 tests, zero-false-positive invariant on the safe fixture set.

## Who runs it

- **Indie hackers** auditing their own Lovable / v0 / Bolt / Replit Agent exports before charging customers
- **Bug bounty hunters** scanning new Product Hunt and Hacker News launches for easy findings
- **Security teams** enforcing a minimum bar on internal Next.js apps
- **Code reviewers** triaging PRs that include a lot of AI-generated code

## CLI reference

```
Usage: vibe-code-triage <path> [options]

Arguments:
  path               Path to repo root (default: .)

Options:
  --checks <list>    Run only specific check IDs (e.g., VC1,VC3,VC7)
  --json             Machine-readable JSON output
  --sarif            SARIF 2.1.0 output for GitHub code scanning
  --fail-on <level>  Exit non-zero on severity >= level
  --ignore <glob>    Additional path to ignore (repeatable)
  --version
  --help, -h
```

## CI integration

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with: { node-version: '20' }
- run: npx valtik-vibe-code-triage . --sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```

Or as a hard gate:

```yaml
- run: npx valtik-vibe-code-triage . --fail-on high
```

## Deep-dive on each check

### VC1 Supabase RLS disabled

Walks `supabase/migrations/*.sql` (and plain `migrations/*.sql`). For every `CREATE TABLE`, verifies there's a corresponding `ALTER TABLE <name> ENABLE ROW LEVEL SECURITY` somewhere in the migration tree. Missing one means the anon key can read and write every row in that table.

Fix: `ALTER TABLE "<table>" ENABLE ROW LEVEL SECURITY;` plus a `CREATE POLICY ... USING (owner_id = auth.uid())`.

### VC2 Permissive RLS policy

Flags three patterns:

- `USING (true)` allows everything
- `USING (auth.role() = 'authenticated')` alone, any logged-in user can read every tenant's rows
- Missing `USING` clause on `SELECT` / `UPDATE` / `DELETE` / `ALL` policies

### VC3 Service-role key exposed to client

Catches `SUPABASE_SERVICE_ROLE_KEY` references in files under `app/`, `pages/`, `components/`, `src/`, excluding `api/` and `server/`. Also always flags `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`, the `NEXT_PUBLIC_` prefix forces the value into the client bundle.

### VC4 Clerk unsafeMetadata used for auth

`unsafeMetadata` is client-writable by design. Any signed-in user can call `user.update({ unsafeMetadata: { role: "admin" } })` and flip an authorization check. Use `publicMetadata` (server-writable, client-readable) or `privateMetadata` (server-only) instead.

### VC5 Route handler missing auth

Walks `app/api/**/route.ts` and `pages/api/**`. If the handler writes (insert, update, delete, upsert, create) and has no auth call (`auth()`, `getAuth()`, `currentUser()`, `getSession()`, etc.) then HIGH. If it's read-only but returns sensitive fields then MEDIUM. Webhook paths are skipped.

### VC6 AI-hallucinated / typosquat package

Parses `package.json` dependencies. Matches against a curated list of known AI-hallucinated package names plus Levenshtein distance 2 to popular-package names.

### VC7 Hardcoded secret

Regex patterns for `sk_live_`, `sk_test_`, `ghp_`, `gho_`, `AKIA`, `AIza`, OpenAI `sk-`, Anthropic `sk-ant-`, JWTs, SendGrid, Twilio, and other common formats. Skips `.env*`, lock files, and obvious placeholder contexts.

### VC8 Missing CSRF on state-changing endpoint

For POST / PUT / PATCH / DELETE handlers that mutate state, looks for any CSRF indicator: a CSRF token, SameSite cookie, Turnstile or hCaptcha verification, origin check, webhook signature, or an auth call.

### VC9 .env file committed

Flags tracked `.env`, `.env.local`, `.env.production`, etc. `.env.example` / `.env.template` / `.env.sample` are always allowed.

### VC10 Dangerous CORS

Flags `Access-Control-Allow-Origin: *` combined with credential-carrying behavior, and `cors({ origin: true })` patterns that reflect arbitrary origins.

## Limitations

- Regex-based, not an AST walker. Expect false positives on novel patterns and false negatives on obfuscation
- Scans plain text only, skips minified JS
- File reads capped at 2 MB
- Not a replacement for runtime black-box testing. Pair with [`rls-tester`](https://github.com/TreRB/rls-tester) for live tenant isolation proofs

## Disclaimer

You must have authorization to scan any repository you don't own. This tool reports possible anti-patterns. Confirm impact manually before filing bug reports or bounty submissions.

## License

MIT (c) 2026 Valtik Studios LLC
