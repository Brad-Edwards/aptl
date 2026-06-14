/**
 * Unit tests for the SvelteKit layout server load function (ADR-039).
 *
 * Covers env-var pass-through for wsToken and apiHost, including defaults
 * when the env vars are absent.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockEnv = vi.hoisted(
	(): Record<string, string | undefined> => ({
		APTL_API_TOKEN: undefined,
		APTL_API_HOST: undefined
	})
);

vi.mock('$env/dynamic/private', () => ({ env: mockEnv }));

import { load } from '../../src/routes/+layout.server';

describe('layout load', () => {
	beforeEach(() => {
		mockEnv.APTL_API_TOKEN = undefined;
		mockEnv.APTL_API_HOST = undefined;
	});

	it('returns wsToken from env when configured', () => {
		mockEnv.APTL_API_TOKEN = 'layout-test-token';
		const data = load({} as Parameters<typeof load>[0]);
		expect(data.wsToken).toBe('layout-test-token');
	});

	it('returns empty string for wsToken when APTL_API_TOKEN is absent', () => {
		mockEnv.APTL_API_TOKEN = undefined;
		const data = load({} as Parameters<typeof load>[0]);
		expect(data.wsToken).toBe('');
	});

	it('returns apiHost from env when configured', () => {
		mockEnv.APTL_API_HOST = 'myhost:9000';
		const data = load({} as Parameters<typeof load>[0]);
		expect(data.apiHost).toBe('myhost:9000');
	});

	it('returns default apiHost when APTL_API_HOST is absent', () => {
		mockEnv.APTL_API_HOST = undefined;
		const data = load({} as Parameters<typeof load>[0]);
		expect(data.apiHost).toBe('127.0.0.1:8400');
	});
});
