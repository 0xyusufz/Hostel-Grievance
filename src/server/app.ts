import { Hono } from 'hono';
import type { Database } from 'better-sqlite3';
import type { AppEnv } from './env.ts';
import { handleError, HttpError } from './http/errors.ts';
import { authRoutes } from './routes/auth.ts';
import { grievanceRoutes } from './routes/grievances.ts';
import { attachmentRoutes } from './routes/attachments.ts';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';

export type CreateAppOptions = {
	db: Database;
	uploadsDir: string;
};

// add to .env.example -> FRONTEND_ORIGIN=http://localhost:5173
const ALLOWED_ORIGINS = new Set(
	(process.env.FRONTEND_ORIGIN ?? 'http://localhost:5173')
		.split(',')
		.map(s => s.trim())
		.filter(Boolean)
);

export function createApp(options: CreateAppOptions) {
	const app = new Hono<AppEnv>();

	app.use('*', secureHeaders());

	app.use('*', async (c, next) => {
		c.set('db', options.db);
		c.set('uploadsDir', options.uploadsDir);
		await next();
	});

	app.use('/api/*', cors({
		origin: (origin) => {
			// same-origin / curl / vitest (no Origin header) -> no CORS header needed
			if (!origin) return null;
			return ALLOWED_ORIGINS.has(origin) ? origin : null;
		},
		credentials: true,
		allowMethods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
		allowHeaders: ['Content-Type'],
		maxAge: 600,
	}));

	app.onError((err, c) => handleError(err, c));
	app.notFound((c) => c.json({ error: 'Not found.', code: 'not_found' }, 404));

	app.get('/api/health', (c) => c.json({ ok: true }));
	app.route('/api', authRoutes);
	app.route('/api/grievances', grievanceRoutes);
	app.route('/api/attachments', attachmentRoutes);

	app.all('/api/*', () => {
		throw new HttpError(404, 'not_found', 'Not found.');
	});

	return app;
}