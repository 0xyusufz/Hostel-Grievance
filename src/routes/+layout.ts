import { redirect } from '@sveltejs/kit';
import type { LayoutLoad } from './$types';
import type { User } from '$lib/types';

export const ssr = false;

export const load: LayoutLoad = async ({ url, fetch }) => {
	// always verify httpOnly cookie via backend, not localStorage
	let user: User | null = null;
	try {
		const res = await fetch('/api/me', { credentials: 'include' });
		if (res.ok) {
			const json = (await res.json()) as { user: User };
			user = json.user;
			// sync cache for UI, not for auth decision
			try { localStorage.setItem('hg.session.user', JSON.stringify(user)); } catch { }
		}
	} catch {
		// network fail -> keep null -> redirect to login
	}

	if (url.pathname === '/login') {
		if (user) redirect(307, user.role === 'warden' ? '/warden' : '/student');
		return {};
	}
	if (!user) {
		try { localStorage.removeItem('hg.session.user'); } catch { }
		redirect(307, '/login');
	}
	const prefix = user.role === 'warden' ? '/warden' : '/student';
	if (!url.pathname.startsWith(prefix)) redirect(307, prefix);
	return {};
};