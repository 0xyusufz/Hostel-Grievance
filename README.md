# HostelGrievance

University hostel grievance portal — Svelte 5 UI plus a small local Hono + SQLite API. Built as a security-lab baseline, not a production platform.

## Install

```sh
npm install
```

## Database

SQLite lives at `data/hostel.db`. Attachment bytes live in `uploads/`.

```sh
npm run db:reset
```

This recreates the seeded database (3 students, 1 warden, 8 grievances, comments, and sample images).

Development logins:

| Role | Email | Password |
| --- | --- | --- |
| Student | `student@example.test` | `student123` |
| Warden | `warden@example.test` | `warden123` |

Additional students (`priya@example.test`, `rohan@example.test`) also use `student123`.

## Run

```sh
# Frontend only (run the API separately for live workflows)
npm run dev

# API only — http://127.0.0.1:3001
npm run dev:api

# Frontend + API (Vite proxies /api → the Hono server)
npm run dev:all
```

## Check and test

```sh
npm run typecheck
npm test
```

The UI talks to the Hono API through `$lib/services` (`credentials: 'include'`). Vite proxies `/api` to port 3001.

The frontend route guard is the authoritative role boundary for navigation; the API handles the data requests behind those routes.

## Security hardening challenge

Treat this repository as an application that must be hardened before public deployment. The goal is to preserve legitimate student and warden workflows while reducing unauthorized access, unsafe input handling, data exposure, and operational blast radius.

You may use any reasonable development or security tools, but findings must be explained and verified. Scanner output by itself is not a submission.

## Submission expectations

Submit a separate package with this structure:

```text
submission/
├── source/
├── deployment/
├── SECURITY.md
├── THREAT-MODEL.md
├── HARDENING.md
└── TEST-EVIDENCE/
```

`HARDENING.md` must contain one concise row per finding using this format:

```text
| ID | Finding | Risk | Change | Verification | Residual Risk |
|----|---------|------|--------|--------------|---------------|
| H-01 | ... | ... | ... | ... | ... |
```

Use your own finding IDs. For each entry, explain what you found, why it matters, what changed, how you verified it, and what risk remains.

`THREAT-MODEL.md` should describe the assets, actors, trust boundaries, authentication and authorization boundaries, data flows, filesystem and runtime boundaries, network assumptions, and important attack paths. Use any clear methodology.

`SECURITY.md` should summarize the protected posture, major changes, remaining risks, deployment assumptions, verification evidence, and the blast radius that remains if one important control fails.

`TEST-EVIDENCE/` should contain commands, test output, screenshots, or short reproducible examples that support the claims. Keep documentation proportional to the security outcome: a finding earns credit when its consequence, remediation, and verification are clear.
