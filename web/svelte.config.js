import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		adapter: adapter({ fallback: 'index.html' }),
		// Strict CSP (UI-008a / ADR-039). The session header token lives in
		// sessionStorage, which is XSS-readable; a strict script-src is the
		// mitigation. `mode: 'hash'` lets SvelteKit hash its own bootstrap inline
		// script (the only inline script) so `script-src 'self'` holds with no
		// 'unsafe-inline'. `style-src` keeps 'unsafe-inline' because xterm.js and
		// Svelte inject inline styles (not a script-execution vector).
		// `connect-src 'self'` covers same-origin fetch, the SSE stream, and the
		// terminal WebSocket. Delivered as a <meta> tag for the prerendered SPA
		// shell, so it applies behind both `aptl web serve` and the Caddy proxy.
		csp: {
			mode: 'hash',
			directives: {
				'default-src': ['self'],
				'script-src': ['self'],
				'style-src': ['self', 'unsafe-inline'],
				'img-src': ['self', 'data:'],
				'font-src': ['self'],
				'connect-src': ['self'],
				'object-src': ['none'],
				'base-uri': ['self'],
				'frame-ancestors': ['none'],
				'form-action': ['self']
			}
		}
	}
};

export default config;
