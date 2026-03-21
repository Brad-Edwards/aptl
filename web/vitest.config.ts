import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vitest/config';

export default defineConfig({
	plugins: [sveltekit()],
	resolve: {
		// Use browser bundle for Svelte 5 so mount() is available in jsdom tests
		conditions: ['browser']
	},
	test: {
		include: ['tests/**/*.test.ts'],
		environment: 'jsdom',
		setupFiles: ['tests/setup.ts'],
		coverage: {
			provider: 'v8',
			reporter: ['text', 'lcov'],
			reportsDirectory: 'coverage',
			include: ['src/**/*.ts', 'src/**/*.svelte'],
			exclude: ['src/**/*.d.ts']
		}
	}
});
