import type { User } from '$lib/types';
import { authService } from '$lib/services';

let current = $state<User | null>(null);
let ready = $state(false);

// hydrate from httpOnly cookie via backend, not localStorage
if (typeof window !== 'undefined') {
	fetch('/api/me', { credentials: 'include' })
		.then(async (r) => {
			if (r.ok) {
				const j = (await r.json()) as { user: User };
				current = j.user;
				try { localStorage.setItem('hg.session.user', JSON.stringify(j.user)); } catch { }
			} else {
				current = null;
				try { localStorage.removeItem('hg.session.user'); } catch { }
			}
		})
		.catch(() => {
			// fallback to cache only for UI skeleton, +layout.ts will redirect
			current = authService.restore();
		})
		.finally(() => (ready = true));
}

export function getSession(): User | null { return current; }
export function isReady(): boolean { return ready; }
export function isStudent(): boolean { return current?.role === 'student'; }
export function isWarden(): boolean { return current?.role === 'warden'; }

export async function signIn(email: string, password: string): Promise<{ ok: boolean; error?: string }> {
	const result = await authService.signIn(email, password);
	if (result.ok) {
		// re-read from server to ensure cookie issued
		try {
			const r = await fetch('/api/me', { credentials: 'include' });
			if (r.ok) current = ((await r.json()) as { user: User }).user;
			else current = result.user;
		} catch {
			current = result.user;
		}
		return { ok: true };
	}
	return { ok: false, error: result.error };
}

export async function signOut(): Promise<void> {
	await authService.signOut();
	current = null;
	try { localStorage.removeItem('hg.session.user'); } catch { }
}