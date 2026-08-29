# SECURITY.md — HostelGrievance Hardened Posture

## Protected posture
Auth = `httpOnly` `hg_session` `scrypt` + `SameSite=Lax` `Secure` (prod) + server `expires_at` + `destroySession` on login/logout. AuthZ = `assertCanViewGrievance` on every `grievance/attachment/comment` read/write. CORS = whitelist `FRONTEND_ORIGIN` only + `secureHeaders`. Upload = random `16B hex` filename + `resolve(uploadsDir)` guard + magic sniff `PNG/JPEG/GIF/WEBP` `2MB`. Input = `<>` stripped, `LIMIT 100` on list. Errors = generic `Internal server error`.
`better-sqlite3` `?` placeholders -> no SQLi. No Redis/Firebase/OAuth/SSRF surface.

## Major changes (from codebase)
`app.ts:23` `*+credentials`->whitelist, `session.ts:49,29,36` cookie flags + expiry + destroy, `passwords.ts:3` `sha256`->`scrypt 64B+16B salt`, `auth.ts:11,36` `429 5/15min` + dummy verify + rotation, `grievances.ts:200,121,135,233,187` IDOR + `PATCH` escalation + traversal, `attachments.ts:10` IDOR, `storage/attachments.ts:35,57,39` random name + resolve + sniff, `comment-timeline.svelte:49` ` {@html}`->sanitize, `errors.ts:25` leak->generic, `queries.ts:98` `${table}`+no LIMIT->whitelist+LIMIT, `seed.ts:21` prod guard + env passwords, `+layout.ts:13`/`auth.svelte.ts:11`/`api.ts:41` `localStorage` trust->`fetch /api/me` truth.

## Deployment assumptions
`NODE_ENV=production` + `FRONTEND_ORIGIN=https://app.example` (comma sep), `HOSTEL_DB_PATH`, `HOSTEL_UPLOADS_DIR`, `ALLOW_SEED` unset (no default `student123/warden123`), `SEED_*_PASSWORD` set if seed needed, HTTPS terminates before Hono (Secure cookie), `better-sqlite3` WAL, single instance (rate-limit in-memory).

## Verification evidence
`npx vitest run --reporter=verbose` 14 pass (IDOR 403, stolen att 403, warden-only status, logout 401, expiry 401, traversal 400, CORS evil blocked, 404 no sqlite/stack). `npx tsx /tmp/exploit2.mjs` before `200` leak `GRV-0003` -> after `403`. `npx tsx /tmp/cors.mjs` `Set-Cookie HttpOnly; SameSite=Lax` + `ACAO` not `evil.com`. `curl -H Origin:evil.com` no `ACAO`. `form file ../../evil.txt` no `../` file.

## H-017 Rate Limiting (Verified 2026-08-29)
H-017 risk: authenticated `POST /api/grievances`, `POST /api/grievances/:id/comments`, `POST /api/grievances/:id/attachments` had no abuse protection -> spam/storage exhaustion. Implemented `src/server/http/rateLimit.ts` reusable in-memory `Map` limiter `createRateLimiter({windowMs,max})` with lazy + `60s` interval `unref` cleanup, separate buckets `grievance:create 5/hour/user`, `comment:create 20/hour/user`, `attachment:create 10/hour/user`, key=`authenticated user.id` after `requireUser`/`assertCanViewGrievance`, `HTTP 429 bad_request` before DB/file write. Preserved login `5/15min ip:email` unchanged, no `GET` limits, no global limiter. Verified `vitest 22 pass` `TEST A-G` `429` per-user/per-route isolation + no record/file on reject. Residual: process-local/in-memory not shared across instances.

## Remaining risks (Low)
In-memory rate-limit not distributed (process-local, see H-017), sequential `GRV-0001` enumerable (blocked by 403, consider UUID), no CAPTCHA/WAF, existing `sha256` hashes need reseed, no 2FA.

## Blast radius if one control fails
CORS bypass alone -> still `403` IDOR + `httpOnly` blocks theft. `assertCanViewGrievance` bypass alone -> still `SameSite=Lax` + CORS whitelist block cross-site exfil. Session `httpOnly` bypass alone -> still `scrypt` + `429` + `expiry` limit replay. Single control failure does not give full data dump.


