import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vitest/config';

export default defineConfig({
	plugins: [sveltekit()],
	test: {
		include: ['tests/**/*.test.ts'],
		environment: 'jsdom',
		setupFiles: ['tests/setup.ts'],
		coverage: {
			provider: 'v8',
			reporter: ['text', 'lcov'],
			reportsDirectory: 'coverage'
		}
	}
});
