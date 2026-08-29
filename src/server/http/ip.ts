import type { Context } from 'hono';
import { isIP } from 'node:net';

function isValidIp(s: string): boolean {
	return isIP(s) !== 0;
}

export function getClientIp(c: Context): string {
	if (process.env.TRUST_PROXY === 'true') {
		const xff = c.req.header('x-forwarded-for');
		if (xff) {
			const first = xff.split(',')[0]?.trim();
			if (first && isValidIp(first)) return first;
		}
		const xri = c.req.header('x-real-ip');
		if (xri) {
			const trimmed = xri.trim();
			if (isValidIp(trimmed)) return trimmed;
		}
		// Forwarded header intentionally ignored - not needed for current deployment
	}
	const incoming = (c.env as Record<string, unknown>)?.incoming as { socket?: { remoteAddress?: string } } | undefined;
	const addr = incoming?.socket?.remoteAddress;
	if (typeof addr === 'string' && addr) return addr;
	return '127.0.0.1';
}
