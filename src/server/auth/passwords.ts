import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const KEYLEN = 64;

export function hashPassword(password: string): string {
	if (!password || password.length < 8) throw new Error('Password too short');
	const salt = randomBytes(16).toString('hex');
	const derived = scryptSync(password, salt, KEYLEN).toString('hex');
	return `scrypt:${salt}:${derived}`;
}

export function verifyPassword(password: string, stored: string): boolean {
	const parts = stored.split(':');

	if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
	const [, salt, hash] = parts;
	if (!salt || !hash) return false;
	try {
		const derived = scryptSync(password, salt, KEYLEN);
		const expected = Buffer.from(hash, 'hex');
		if (derived.length !== expected.length) return false;
		return timingSafeEqual(derived, expected);
	} catch {
		return false;
	}
}
