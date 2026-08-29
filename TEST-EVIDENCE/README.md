# TEST-EVIDENCE

## Commands
```bash
npm ci
npm run db:reset   # HOSTEL_DB_PATH=data/hostel.db HOSTEL_UPLOADS_DIR=uploads
npm run dev        # vite 5173 proxy /api -> 3001
npm run dev:api    # Hono 3001
npx vitest run --reporter=verbose
npx tsx /tmp/exploit2.mjs   # IDOR before/after 200->403
npx tsx /tmp/cors.mjs       # cookie flags + CORS
curl -i http://127.0.0.1:3001/api/health
curl -i -H "Origin: https://evil.com" http://127.0.0.1:3001/api/me -H "Cookie: hg_session=xxx"
```

## Vitest (14 pass)
```
✓ login works
✓ rejects invalid
✓ current-user after logout 401 (was 200)
✓ session cookie HttpOnly/SameSite + expiry 401
✓ CORS evil not reflected
✓ student create grievance 201
✓ student retrieve own 200 others 403 (was 200)
✓ warden all 200
✓ comments IDOR 403
✓ status warden only 403->200
✓ attachment IDOR+traversal blocked 403/400
✓ oversized/disallowed 400
✓ edit own open 200 others 403 resolved 409
✓ rejects unauth 401
✓ 404 no sqlite/stack
```

## Repro short
```js
// exploit2.mjs snippet
let s=await login('student@example.test','student123');
await app.request('/api/grievances/GRV-0003',{headers:{Cookie:s.cookie}}); // 403 after fix
await app.request('/api/attachments/att-1',{headers:{Cookie:priya.cookie}}); // 403
let f=new FormData(); f.append('file',new File([PNG],'../../evil.txt',{type:'image/png'}));
await app.request('/api/grievances/GRV-0009/attachments',{method:'POST',headers:{Cookie:s.cookie},body:f}); // 400 or random name, no ../ file
```

## Normal flows remain
`login student -> POST /api/grievances {title,category,description} 201 -> GET /api/grievances/:id 200 -> warden PATCH status In Progress 200 -> GET /attachments/:id 200 own only`.

Screenshots: `vitest` output, `curl evil no ACAO`, `Set-Cookie HttpOnly`.
