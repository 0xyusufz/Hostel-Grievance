import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import type { AppEnv } from '../env.ts';
import { createSession, clearSessionCookie, destroySession, requireUser, setSessionCookie } from '../auth/session.ts';
import { verifyPassword } from '../auth/passwords.ts';
import { findUserByEmail } from '../db/queries.ts';
import { toPublicUser } from '../db/map.ts';
import { HttpError } from '../http/errors.ts';
import { SESSION_COOKIE } from '../config.ts';
import { getClientIp } from '../http/ip.ts';
import { audit } from '../http/audit.ts';

export const authRoutes = new Hono<AppEnv>();

// simple in-memory rate-limit: 5 fails / 15min per IP+email — IP via getClientIp (TRUST_PROXY aware)
const fails = new Map<string, { n: number; reset: number }>();
export function __clearLoginRateLimits() { fails.clear(); }
function checkRate(c: any, email: string) {
	const key = getClientIp(c) + ':' + email;
	const now = Date.now();
	const e = fails.get(key);
	if (e && now < e.reset && e.n >= 5) {
		audit(c, 'rate_limit.hit', { reason: 'login', email, result: 'blocked' });
		throw new HttpError(429, 'bad_request', 'Too many attempts, try later.');
	}
	if (e && now >= e.reset) fails.delete(key);
}
function recordFail(email: string, c: any) {
	const key = getClientIp(c) + ':' + email;
	const e = fails.get(key);
	if (!e) fails.set(key, { n: 1, reset: Date.now() + 15 * 60 * 1000 });
	else e.n++;
}

authRoutes.post('/login', async (c) => {
	const db = c.get('db');
	let body: unknown;
	try { body = await c.req.json(); } catch { throw new HttpError(400, 'bad_request', 'Request body must be JSON.'); }
	if (!body || typeof body !== 'object') throw new HttpError(400, 'bad_request', 'Request body must be JSON.');
	const email = 'email' in body && typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
	const password = 'password' in body && typeof body.password === 'string' ? body.password : '';
	if (!email || !password) throw new HttpError(400, 'bad_request', 'Email and password are required.');
	if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, 'bad_request', 'Invalid email.');
	checkRate(c, email);

	const user = findUserByEmail(db, email);
	// dummy verify to keep timing constant when user not found
	const ok = user ? verifyPassword(password, user.password_hash) : verifyPassword(password, 'scrypt:00000000000000000000000000000000:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000');
	if (!user || !ok) {
		recordFail(email, c);
		audit(c, 'auth.login.failure', { email, reason: 'invalid_credentials', result: 'failure' });
		throw new HttpError(401, 'unauthenticated', 'Invalid email or password.');
	}
	// rotation: destroy old session if present
	const old = getCookie(c, SESSION_COOKIE);
	if (old) destroySession(db, old);
	fails.delete(getClientIp(c) + ':' + email);
	const token = createSession(db, user.id);
	setSessionCookie(c, token);
	audit(c, 'auth.login.success', { userId: user.id, role: user.role, email, result: 'success' });
	return c.json({ user: toPublicUser(user) });
});

authRoutes.post('/logout', (c) => {
	const db = c.get('db');
	const t = getCookie(c, SESSION_COOKIE);
	let userId: string | undefined;
	if (t) {
		const u = c.get('db').prepare('SELECT user_id FROM sessions WHERE token=?').get(t) as { user_id?: string } | undefined;
		userId = u?.user_id;
		destroySession(db, t);
	}
	clearSessionCookie(c);
	audit(c, 'auth.logout', { userId, result: 'success' });
	return c.json({ ok: true, success: "logout successfully" });
});

authRoutes.get('/me', (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);
	return c.json({ user: toPublicUser(user) });
});