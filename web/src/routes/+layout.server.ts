import type { LayoutServerLoad } from './$types';
import { env } from '$env/dynamic/private';

/**
 * Provide per-request server data to the browser layout.
 *
 * wsToken is the API bearer token rendered into the page at request time (not
 * baked into the static bundle). The browser uses it only for the WebSocket
 * subprotocol header, never in a URL. apiHost is the browser-visible host:port
 * for direct WebSocket connections (bypasses the SvelteKit server-side proxy
 * since WebSocket proxying requires separate infrastructure).
 */
export const load: LayoutServerLoad = () => {
	return {
		apiHost: env.APTL_API_HOST ?? '127.0.0.1:8400',
		wsToken: env.APTL_API_TOKEN ?? ''
	};
};
