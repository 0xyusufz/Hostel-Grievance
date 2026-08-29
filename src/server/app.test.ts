import { mkdtempSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from './app.ts';
import { openDatabase } from './db/connection.ts';
import { seedDatabase } from './db/seed.ts';
import { __clearRateLimits } from './http/rateLimit.ts';

const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');

function cookieHeader(res: Response): string {
	const anyHeaders = res.headers as Headers & { getSetCookie?: () => string[] };
	const list = anyHeaders.getSetCookie?.() ?? [];
	if (list.length > 0) return list.map((v) => v.split(';')[0]).join('; ');
	const raw = res.headers.get('set-cookie');
	return raw ? raw.split(';')[0] : '';
}
function setCookieHeader(res: Response): string {
	const anyHeaders = res.headers as Headers & { getSetCookie?: () => string[] };
	const list = anyHeaders.getSetCookie?.() ?? [];
	if (list.length > 0) return list[0];
	return res.headers.get('set-cookie') ?? '';
}
async function login(app: ReturnType<typeof createApp>, email: string, password: string) {
	const res = await app.request('/api/login', {
		method: 'POST', headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email, password })
	});
	const json = await res.json().catch(() => ({})) as any;
	return { res, json, cookie: cookieHeader(res), setCookie: setCookieHeader(res) };
}

describe('HostelGrievance API baseline + security', () => {
	let dir: string;
	let app: ReturnType<typeof createApp>;
	let db: ReturnType<typeof openDatabase>;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'hg-api-'));
		db = openDatabase(join(dir, 'hostel.db'));
		const uploadDir = join(dir, 'uploads');
		seedDatabase(db, uploadDir);
		app = createApp({ db, uploadsDir: uploadDir });
	});
	afterEach(() => {
		__clearRateLimits();
		try { db.close(); } catch { }
		rmSync(dir, { recursive: true, force: true });
	});

	it('login works for dummy student and warden accounts', async () => {
		const student = await login(app, 'student@example.test', 'student123');
		expect(student.res.status).toBe(200);
		expect(student.json.user.role).toBe('student');
		expect(student.json.user.password).toBeUndefined();
		expect(student.cookie).toContain('hg_session=');
		const warden = await login(app, 'warden@example.test', 'warden123');
		expect(warden.res.status).toBe(200);
		expect(warden.json.user.role).toBe('warden');
	});
	it('rejects invalid credentials', async () => {
		const bad = await login(app, 'student@example.test', 'wrong');
		expect(bad.res.status).toBe(401);
	});
	it('current-user works after login and fails after logout', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		expect((await app.request('/api/me', { headers: { Cookie: cookie } })).status).toBe(200);
		expect((await app.request('/api/me')).status).toBe(401);
		await app.request('/api/logout', { method: 'POST', headers: { Cookie: cookie } });
		expect((await app.request('/api/me', { headers: { Cookie: cookie } })).status).toBe(401);
	});
	it('session cookie has httpOnly, SameSite, and expiry is enforced', async () => {
		const { setCookie, cookie } = await login(app, 'student@example.test', 'student123');
		expect(setCookie.toLowerCase()).toContain('httponly');
		expect(setCookie.toLowerCase()).toContain('samesite');
		// expire in DB -> must be 401
		const token = cookie.split('=')[1];
		db.prepare('UPDATE sessions SET expires_at=? WHERE token=?').run(new Date(Date.now() - 10000).toISOString(), token);
		expect((await app.request('/api/me', { headers: { Cookie: cookie } })).status).toBe(401);
	});
	it('CORS does not reflect evil origin with credentials', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const res = await app.request('/api/me', { headers: { Origin: 'https://evil.com', Cookie: cookie } });
		expect(res.headers.get('access-control-allow-origin')).not.toBe('https://evil.com');
	});
	it('student can create a grievance', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const res = await app.request('/api/grievances', {
			method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie },
			body: JSON.stringify({ title: 'Broken cupboard hinge', category: 'Room', description: 'The cupboard hinge in B-204 is broken and the door will not close properly.' })
		});
		expect(res.status).toBe(201);
	});
	it('student can retrieve own grievance but not others (IDOR)', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		expect((await app.request('/api/grievances/GRV-0001', { headers: { Cookie: cookie } })).status).toBe(200);
		expect((await app.request('/api/grievances/GRV-0003', { headers: { Cookie: cookie } })).status).toBe(403);
		const list = await (await app.request('/api/grievances', { headers: { Cookie: cookie } })).json() as any;
		expect(list.data.every((g: any) => g.studentId === 'stu-1')).toBe(true);
	});
	it('warden can access all', async () => {
		const { cookie } = await login(app, 'warden@example.test', 'warden123');
		expect((await app.request('/api/grievances', { headers: { Cookie: cookie } })).status).toBe(200);
		expect((await app.request('/api/grievances/GRV-0003', { headers: { Cookie: cookie } })).status).toBe(200);
	});
	it('comments IDOR blocked', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		expect((await app.request('/api/grievances/GRV-0003/comments', { headers: { Cookie: cookie } })).status).toBe(403);
		expect((await app.request('/api/grievances/GRV-0003/comments', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: JSON.stringify({ body: 'hi' }) })).status).toBe(403);
	});
	it('status change warden only', async () => {
		const student = await login(app, 'student@example.test', 'student123');
		expect((await app.request('/api/grievances/GRV-0001', { method: 'PATCH', headers: { 'Content-Type': 'application/json', Cookie: student.cookie }, body: JSON.stringify({ status: 'Resolved' }) })).status).toBe(403);
		const warden = await login(app, 'warden@example.test', 'warden123');
		const upd = await app.request('/api/grievances/GRV-0008', { method: 'PATCH', headers: { 'Content-Type': 'application/json', Cookie: warden.cookie }, body: JSON.stringify({ status: 'In Progress' }) });
		expect(upd.status).toBe(200);
	});
	it('attachment IDOR + traversal blocked', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		// create grievance then try traversal filename
		const created = await (await app.request('/api/grievances', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: JSON.stringify({ title: 'Need a photo on file', category: 'Other', description: 'Filing this so I can attach a photo of the damaged locker door.' }) })).json() as any;
		const id = created.data.id;
		const form = new FormData(); form.append('file', new File([PNG], '../../evil.txt', { type: 'image/png' }));
		const up = await app.request(`/api/grievances/${id}/attachments`, { method: 'POST', headers: { Cookie: cookie }, body: form });
		// fixed server must not store ../../evil.txt -> should be random hex name and not escape
		if (up.status === 201) {
			const meta = await up.json() as any;
			expect(meta.data.filename).not.toContain('..');
			expect(existsSync(join(dir, 'evil.txt'))).toBe(false);
			expect(existsSync(join(dir, 'uploads', '..', 'evil.txt'))).toBe(false);
		} else expect(up.status).toBe(400);
		// other student cannot fetch att-1
		const other = await login(app, 'priya@example.test', 'student123');
		expect((await app.request('/api/attachments/att-1', { headers: { Cookie: other.cookie } })).status).toBe(403);
	});
	it('rejects oversized and disallowed attachments', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const huge = new Uint8Array(2 * 1024 * 1024 + 1);
		const over = new FormData(); over.append('file', new File([huge], 'big.png', { type: 'image/png' }));
		expect((await app.request('/api/grievances/GRV-0008/attachments', { method: 'POST', headers: { Cookie: cookie }, body: over })).status).toBe(400);
		const invalid = new FormData(); invalid.append('file', new File(['not-an-image'], 'notes.txt', { type: 'text/plain' }));
		expect((await app.request('/api/grievances/GRV-0008/attachments', { method: 'POST', headers: { Cookie: cookie }, body: invalid })).status).toBe(400);
	});
	it('lets student edit own open but not others or resolved', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		expect((await app.request('/api/grievances/GRV-0008', { method: 'PATCH', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: JSON.stringify({ title: 'Mess tables still dirty before dinner' }) })).status).toBe(200);
		const other = await login(app, 'priya@example.test', 'student123');
		expect((await app.request('/api/grievances/GRV-0008', { method: 'PATCH', headers: { 'Content-Type': 'application/json', Cookie: other.cookie }, body: JSON.stringify({ title: 'Should not work' }) })).status).toBe(403);
		const rohan = await login(app, 'rohan@example.test', 'student123');
		expect((await app.request('/api/grievances/GRV-0004', { method: 'PATCH', headers: { 'Content-Type': 'application/json', Cookie: rohan.cookie }, body: JSON.stringify({ title: 'Trying to change resolved' }) })).status).toBe(409);
	});
	it('rejects unauthenticated', async () => { expect((await app.request('/api/grievances')).status).toBe(401); });
	it('404 without leaking internals', async () => {
		const { cookie } = await login(app, 'warden@example.test', 'warden123');
		const res = await app.request('/api/grievances/GRV-9999', { headers: { Cookie: cookie } });
		expect(res.status).toBe(404);
		expect(JSON.stringify(await res.json())).not.toMatch(/sqlite|stack|ENOENT/i);
	});

	// H-017 rate limiting
	it('TEST A — grievance rate limit 5/hour', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		for (let i = 0; i < 5; i++) {
			const res = await app.request('/api/grievances', {
				method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie },
				body: JSON.stringify({ title: `Rate grievance ${i} title`, category: 'Other', description: 'Description must be at least twenty characters long for test.' })
			});
			expect(res.status).toBe(201);
		}
		const before = (db.prepare('SELECT COUNT(*) as n FROM grievances WHERE student_id=?').get('stu-1') as { n: number }).n;
		const blocked = await app.request('/api/grievances', {
			method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie },
			body: JSON.stringify({ title: 'Blocked grievance title', category: 'Other', description: 'Description must be at least twenty characters long for test.' })
		});
		expect(blocked.status).toBe(429);
		const after = (db.prepare('SELECT COUNT(*) as n FROM grievances WHERE student_id=?').get('stu-1') as { n: number }).n;
		expect(after).toBe(before);
	});
	it('TEST B — grievance user isolation', async () => {
		const { cookie: c1 } = await login(app, 'student@example.test', 'student123');
		for (let i = 0; i < 5; i++) {
			await app.request('/api/grievances', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: c1 }, body: JSON.stringify({ title: `Isolate grievance ${i}`, category: 'Other', description: 'Description must be at least twenty characters long for isolation.' }) });
		}
		expect((await app.request('/api/grievances', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: c1 }, body: JSON.stringify({ title: 'Blocked', category: 'Other', description: 'Description must be at least twenty characters long for isolation.' }) })).status).toBe(429);
		const { cookie: c2 } = await login(app, 'priya@example.test', 'student123');
		const res2 = await app.request('/api/grievances', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: c2 }, body: JSON.stringify({ title: 'Priya allowed grievance', category: 'Other', description: 'Description must be at least twenty characters long for isolation.' }) });
		expect(res2.status).toBe(201);
	});
	it('TEST C — comment rate limit 20/hour', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		for (let i = 0; i < 20; i++) {
			const res = await app.request('/api/grievances/GRV-0001/comments', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: JSON.stringify({ body: `comment ${i}` }) });
			expect(res.status).toBe(201);
		}
		const before = (db.prepare('SELECT COUNT(*) as n FROM comments WHERE grievance_id=?').get('GRV-0001') as { n: number }).n;
		const blocked = await app.request('/api/grievances/GRV-0001/comments', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: JSON.stringify({ body: 'blocked comment' }) });
		expect(blocked.status).toBe(429);
		const after = (db.prepare('SELECT COUNT(*) as n FROM comments WHERE grievance_id=?').get('GRV-0001') as { n: number }).n;
		expect(after).toBe(before);
	});
	it('TEST D — comment user isolation', async () => {
		const { cookie: c1 } = await login(app, 'student@example.test', 'student123');
		for (let i = 0; i < 20; i++) await app.request('/api/grievances/GRV-0001/comments', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: c1 }, body: JSON.stringify({ body: `iso ${i}` }) });
		expect((await app.request('/api/grievances/GRV-0001/comments', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: c1 }, body: JSON.stringify({ body: 'blocked' }) })).status).toBe(429);
		const { cookie: c2 } = await login(app, 'priya@example.test', 'student123');
		// priya comments on her own grievance GRV-0003
		const res2 = await app.request('/api/grievances/GRV-0003/comments', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: c2 }, body: JSON.stringify({ body: 'priya allowed' }) });
		expect(res2.status).toBe(201);
	});
	it('TEST E — attachment rate limit 10/hour', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const created = await (await app.request('/api/grievances', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: JSON.stringify({ title: 'Attach rate test grievance', category: 'Other', description: 'Description must be at least twenty characters long for attach.' }) })).json() as any;
		const gid = created.data.id;
		const beforeFiles = readdirSync(join(dir, 'uploads')).length;
		const beforeRows = (db.prepare('SELECT COUNT(*) as n FROM attachments').get() as { n: number }).n;
		for (let i = 0; i < 10; i++) {
			const fd = new FormData(); fd.append('file', new File([PNG], `a${i}.png`, { type: 'image/png' }));
			expect((await app.request(`/api/grievances/${gid}/attachments`, { method: 'POST', headers: { Cookie: cookie }, body: fd })).status).toBe(201);
		}
		const fdBlock = new FormData(); fdBlock.append('file', new File([PNG], 'blocked.png', { type: 'image/png' }));
		expect((await app.request(`/api/grievances/${gid}/attachments`, { method: 'POST', headers: { Cookie: cookie }, body: fdBlock })).status).toBe(429);
		expect((db.prepare('SELECT COUNT(*) as n FROM attachments').get() as { n: number }).n).toBe(beforeRows + 10);
		expect(readdirSync(join(dir, 'uploads')).length).toBe(beforeFiles + 10);
	});
	it('TEST F — attachment user isolation', async () => {
		const { cookie: c1 } = await login(app, 'student@example.test', 'student123');
		const g1 = await (await app.request('/api/grievances', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: c1 }, body: JSON.stringify({ title: 'Attach iso grievance a', category: 'Other', description: 'Description must be at least twenty characters long for isolation attach.' }) })).json() as any;
		for (let i = 0; i < 10; i++) { const fd = new FormData(); fd.append('file', new File([PNG], `a${i}.png`, { type: 'image/png' })); await app.request(`/api/grievances/${g1.data.id}/attachments`, { method: 'POST', headers: { Cookie: c1 }, body: fd }); }
		expect((await (async () => { const fd = new FormData(); fd.append('file', new File([PNG], 'blocked.png', { type: 'image/png' })); return app.request(`/api/grievances/${g1.data.id}/attachments`, { method: 'POST', headers: { Cookie: c1 }, body: fd }); })()).status).toBe(429);
		const { cookie: c2 } = await login(app, 'priya@example.test', 'student123');
		const g2 = await (await app.request('/api/grievances', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: c2 }, body: JSON.stringify({ title: 'Attach iso grievance b', category: 'Other', description: 'Description must be at least twenty characters long for isolation attach.' }) })).json() as any;
		const fd2 = new FormData(); fd2.append('file', new File([PNG], 'priya.png', { type: 'image/png' }));
		expect((await app.request(`/api/grievances/${g2.data.id}/attachments`, { method: 'POST', headers: { Cookie: c2 }, body: fd2 })).status).toBe(201);
	});
	it('TEST G — route bucket isolation', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		for (let i = 0; i < 20; i++) await app.request('/api/grievances/GRV-0001/comments', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: JSON.stringify({ body: `bucket ${i}` }) });
		expect((await app.request('/api/grievances/GRV-0001/comments', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: JSON.stringify({ body: 'blocked' }) })).status).toBe(429);
		// grievance bucket independent
		const gRes = await app.request('/api/grievances', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: JSON.stringify({ title: 'Bucket isolate grievance', category: 'Other', description: 'Description must be at least twenty characters long for bucket.' }) });
		expect(gRes.status).toBe(201);
		// attachment bucket independent
		const gid = (await gRes.json() as any).data.id;
		const fd = new FormData(); fd.append('file', new File([PNG], 'iso.png', { type: 'image/png' }));
		expect((await app.request(`/api/grievances/${gid}/attachments`, { method: 'POST', headers: { Cookie: cookie }, body: fd })).status).toBe(201);
	});
});