import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	server: {
		proxy: {
			'/api': {
				target: 'http://localhost:8400',
				// Preserve the browser's Host so the BFF sees the dev origin as
				// same-origin (UI-008a strict same-origin CSRF/WS gate). With
				// changeOrigin:true the upstream Host would become localhost:8400
				// and same-origin checks on mutating/WS requests would fail.
				changeOrigin: false,
				ws: true
			}
		}
	}
});
