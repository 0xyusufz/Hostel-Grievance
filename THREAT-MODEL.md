# THREAT-MODEL.md — HostelGrievance (STRIDE)

## Assets
`users.password_hash`, `sessions.token`, `grievances` (student private text), `attachments` (images on FS `uploads/`), `comments`, `data/hostel.db`.

## Actors
Student (own `grievanceId`), Warden (all), Anonymous (login), Attacker (XSS/CSRF/IDOR/brute).

## Trust boundaries
1. Browser `localStorage` (untrusted) | `httpOnly Cookie hg_session` -> Hono `requireUser` -> SQLite `users/sessions`. `localStorage` never auth.
2. Client `File.type` (untrusted) -> server `sniffMime` + `ALLOWED_ATTACHMENT_TYPES`.
3. `Origin evil.com` | whitelist `FRONTEND_ORIGIN` -> `cors` middleware.

## Authentication & Authorization boundaries
AuthN: `POST /api/login` `scrypt` verify + `createSession` `32B base64url` -> `Set-Cookie httpOnly Secure SameSite=Lax` `7d`. `GET /api/me` is truth.
AuthZ: `student` `student_id===user.id` else `403`, `warden` all, `PATCH` `student` `title/desc/category` only on own `status!=resolved`, `warden` `status` only, Password Secure with scrypt + per-user 16byte salt.

## Data flows
`login {email,password} -> verify -> session -> cookie -> GET /api/me -> GET /api/grievances -> GET /api/grievances/:id -> GET /attachments/:id (readStoredFile resolve)`. `POST /grievances multipart` -> `bufferFromUpload sniff` -> `writeStoredFile resolve` random name -> `INSERT attachments`. `POST /:id/comments {body} -> sanitize <>`.

## Filesystem & Runtime boundaries
`HOSTEL_UPLOADS_DIR` `resolve(join(dir,stored))` must stay `startsWith(root+sep)`. `data/hostel.db` `PRAGMA foreign_keys=ON` `WAL`. `vite proxy /api -> 127.0.0.1:3001` dev only. No `eval`/`exec`.

## Network assumptions
Same-site `vite:5173` `FRONTEND_ORIGIN`, HTTPS in prod (`Secure` flag), no `*` with credentials, `secureHeaders` (HSTS/CSP/X-Frame). In-memory rate-limit assumes single instance.

## Attack surface
`/api/login`, `/api/grievances*` (`:id`, `:id/comments`, `:id/attachments`), `/api/attachments/:id`, `comment.body {@html}`, `File.type`/`file.name`.

## Important attack paths
1. **IDOR** `stu-1 GET /api/grievances/GRV-0003` -> `grievances.ts:200` -> mitigate `assertCanViewGrievance` -> verify `vitest 403`.
2. **Stored XSS** `POST /grievances/GRV-0003/comments {"body":"<img onerror>"} }` -> `comment-timeline.svelte:49` -> mitigate `sanitizeBody` -> verify `<>` stripped.
3. **CORS exfil** `evil.com fetch /api/me credentials:include` -> `app.ts:23` -> mitigate whitelist -> verify `curl evil no ACAO`.
4. **Session replay** `POST /logout` no `destroy` + no `expires_at` -> mitigate `destroySession` + expiry -> verify `me after logout 401`.
5. **Path traversal** `file.name=../../evil.txt` -> `storage/attachments.ts:35` -> mitigate random name + `resolve` guard -> verify `400` no `../` file.
6. **Brute** `POST /login` -> mitigate `5/15min 429` + dummy verify -> verify `429`.
7. **Mime spoof** `shell.php as image/png` -> mitigate `sniffMime` -> verify `400 content mismatch`.
8. **H-017 Authenticated spam** `stu POST /api/grievances|comments|attachments` loop `100/h` -> `spam/storage exhaustion` -> mitigate `src/server/http/rateLimit.ts` `5/20/10 per hour per user.id` separate buckets `429` before DB/file -> verify `vitest TEST A-G` `429` per-user/per-route isolation. Trust boundary `Browser->API` authenticated `user.id` (not `X-Forwarded-For`), residual process-local only.
