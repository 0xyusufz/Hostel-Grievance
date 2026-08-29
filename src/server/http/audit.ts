import type { Context } from 'hono';
import { getClientIp } from './ip.ts';

type AuditFields = Record<string, unknown>;

export function audit(c: Context, event: string, fields: AuditFields = {}): void {
	const rec: Record<string, unknown> = {
		timestamp: new Date().toISOString(),
		event,
		clientIp: getClientIp(c),
		method: c.req.method,
		path: c.req.path,
		...fields,
	};
	// JSON.stringify safely escapes newlines/injection
	console.log(JSON.stringify(rec));
}
