import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import type { AppConfig } from '../../src/lib/types';

function config(): AppConfig {
	return {
		lab_name: 'aptl',
		network_subnet: '172.20.0.0/16',
		containers: {},
		run_storage_backend: 'local',
		web: {
			build_version: '1',
			allowed_hosts: [],
			public_origin: null,
			deployment_provider: 'docker-compose'
		}
	};
}

describe('config route load', () => {
	beforeEach(() => {
		sessionStorage.clear();
	});

	it('fetches /api/config and returns the projection', async () => {
		const data = config();
		const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(data) });

		const { load } = await import('../../src/routes/config/+page');
		const result = await load({ fetch: mockFetch } as any);

		expect(result.config).toEqual(data);
		expect(result.configError).toBe(false);
		expect(mockFetch).toHaveBeenCalledWith(
			'/api/config',
			expect.objectContaining({ headers: expect.any(Headers) })
		);
	});

	it('degrades to an error state on fetch failure', async () => {
		const mockFetch = vi.fn().mockRejectedValue(new Error('boom'));

		const { load } = await import('../../src/routes/config/+page');
		const result = await load({ fetch: mockFetch } as any);

		expect(result.config).toBeNull();
		expect(result.configError).toBe(true);
	});
});

describe('config page render', () => {
	it('renders the config summary when data is present', async () => {
		const Page = (await import('../../src/routes/config/+page.svelte')).default;
		render(Page, { props: { data: { config: config(), configError: false } } });
		expect(screen.getByRole('heading', { name: 'Config' })).toBeTruthy();
		expect(screen.getByText('aptl')).toBeTruthy();
	});

	it('renders an unavailable state on error', async () => {
		const Page = (await import('../../src/routes/config/+page.svelte')).default;
		render(Page, { props: { data: { config: null, configError: true } } });
		expect(screen.getByText(/currently unavailable/i)).toBeTruthy();
	});
});
