import { HttpError } from './errors.ts';

type Bucket = { count: number; reset: number };

const allBuckets = new Set<Map<string, Bucket>>();
let cleanupStarted = false;

function startCleanup() {
	if (cleanupStarted) return;
	cleanupStarted = true;
	const interval = setInterval(() => {
		const now = Date.now();
		for (const map of allBuckets) {
			for (const [k, v] of map) {
				if (now >= v.reset) map.delete(k);
			}
		}
	}, 60_000);
	// do not keep Node process alive
	// @ts-ignore
	if (typeof interval.unref === 'function') interval.unref();
}

export type RateLimiter = {
	check(userId: string): void;
};

export function createRateLimiter(opts: { windowMs: number; max: number }): RateLimiter {
	const map = new Map<string, Bucket>();
	allBuckets.add(map);
	startCleanup();

	return {
		check(userId: string) {
			const now = Date.now();
			let bucket = map.get(userId);
			if (!bucket || now >= bucket.reset) {
				bucket = { count: 1, reset: now + opts.windowMs };
				map.set(userId, bucket);
				return;
			}
			if (bucket.count >= opts.max) {
				const retryAfter = Math.ceil((bucket.reset - now) / 1000);
				throw new HttpError(429, 'bad_request', `Too many requests, try again in ${retryAfter}s.`);
			}
			bucket.count++;
		}
	};
}

// for tests to isolate
export function __clearRateLimits() {
	for (const map of allBuckets) map.clear();
}
