import { getConfig } from '$lib/api';
import type { AppConfig } from '$lib/types';

/**
 * Load the non-secret configuration projection for the `/config` route.
 *
 * Routes through `getConfig()` (shared API boundary, carries the
 * `X-APTL-Session` header) and threads the load-provided `event.fetch` so the
 * request resolves in every load context. A failure degrades to a stable
 * error state rather than crashing the route.
 */
export async function load({ fetch }): Promise<{
	config: AppConfig | null;
	configError: boolean;
}> {
	try {
		return { config: await getConfig(fetch), configError: false };
	} catch {
		return { config: null, configError: true };
	}
}
