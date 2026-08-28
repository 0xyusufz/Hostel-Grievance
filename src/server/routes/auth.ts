import { Hono } from 'hono';
//get cookie
import { getCookie } from 'hono/cookie';
import type { AppEnv } from '../env.ts';
// session
import { SESSION_COOKIE } from '../config.ts';
// destroy session
import { createSession, clearSessionCookie, requireUser, setSessionCookie, destroySession } from '../auth/session.ts';
import { verifyPassword } from '../auth/passwords.ts';
import { findUserByEmail } from '../db/queries.ts';
import { toPublicUser } from '../db/map.ts';
import { HttpError } from '../http/errors.ts';

export const authRoutes = new Hono<AppEnv>();

authRoutes.post('/login', async (c) => {
	const db = c.get('db');
	let body: unknown;
	try {
		body = await c.req.json();
	} catch {
		throw new HttpError(400, 'bad_request', 'Request body must be JSON.');
	}
	if (!body || typeof body !== 'object') {
		throw new HttpError(400, 'bad_request', 'Request body must be JSON.');
	}
	const email = 'email' in body && typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
	const password = 'password' in body && typeof body.password === 'string' ? body.password : '';
	if (!email || !password) {
		throw new HttpError(400, 'bad_request', 'Email and password are required.');
	}
	const user = findUserByEmail(db, email);
	if (!user || !verifyPassword(password, user.password_hash)) {
		throw new HttpError(401, 'unauthenticated', 'Invalid email or password.');
	}
	const token = createSession(db, user.id);
	setSessionCookie(c, token);
	return c.json({ user: toPublicUser(user) });
});

// logout changes in  file
authRoutes.post('/logout', (c) => {
	const db = c.get('db'); const t = getCookie(c, SESSION_COOKIE);
	if (t) destroySession(db, t); clearSessionCookie(c); return c.json({ ok: true });
});

authRoutes.get('/me', (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);
	return c.json({ user: toPublicUser(user) });
});
