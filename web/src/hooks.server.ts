import type { Handle } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';

/**
 * Server-side proxy for all /api/* requests (ADR-039).
 *
 * The SvelteKit server injects the bearer token so the browser never needs to
 * carry it in request headers or URLs. Streaming responses (SSE) are forwarded
 * unchanged, preserving the EventSource protocol.
 */
export const handle: Handle = async ({ event, resolve }) => {
	if (event.url.pathname.startsWith('/api/')) {
		const apiBase = env.APTL_API_URL ?? 'http://localhost:8400';
		const token = env.APTL_API_TOKEN;

		if (!token) {
			return new Response(JSON.stringify({ detail: 'API token not configured on server' }), {
				status: 503,
				headers: { 'Content-Type': 'application/json' }
			});
		}

		const targetUrl = `${apiBase}${event.url.pathname}${event.url.search}`;

		const reqHeaders = new Headers(event.request.headers);
		reqHeaders.delete('host');
		reqHeaders.set('Authorization', `Bearer ${token}`);

		try {
			const upstream = await fetch(targetUrl, {
				method: event.request.method,
				headers: reqHeaders,
				body: event.request.body,
				// @ts-expect-error — Node.js fetch supports duplex for streaming bodies
				duplex: 'half'
			});

			return new Response(upstream.body, {
				status: upstream.status,
				statusText: upstream.statusText,
				headers: upstream.headers
			});
		} catch {
			return new Response(JSON.stringify({ detail: 'API proxy error' }), {
				status: 502,
				headers: { 'Content-Type': 'application/json' }
			});
		}
	}

	return resolve(event);
};
