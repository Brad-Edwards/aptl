/**
 * Unit tests for the SvelteKit server hook (ADR-039).
 *
 * Covers the auth-proxy logic in hooks.server.ts: Authorization header
 * injection, missing-token 503, upstream-error 502, and pass-through for
 * non-API routes.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

// vi.hoisted() runs before vi.mock hoisting so the reference is available in
// the mock factory closure. Tests modify individual properties between calls.
const mockEnv = vi.hoisted(
	(): Record<string, string | undefined> => ({
		APTL_API_TOKEN: 'test-hook-token',
		APTL_API_URL: undefined
	})
);

vi.mock('$env/dynamic/private', () => ({ env: mockEnv }));

// Import AFTER vi.mock so vitest's hoisting applies the mock first.
import { handle } from '../../src/hooks.server';

function makeEvent(
	pathname: string,
	method = 'GET',
	headers: Record<string, string> = {}
) {
	const url = `http://localhost${pathname}`;
	return {
		url: new URL(url),
		request: new Request(url, { method, headers })
	};
}

describe('handle', () => {
	beforeEach(() => {
		mockEnv.APTL_API_TOKEN = 'test-hook-token';
		mockEnv.APTL_API_URL = undefined;
		vi.restoreAllMocks();
	});

	it('proxies /api/* requests with an Authorization header', async () => {
		const fetchMock = vi.fn().mockResolvedValue(
			new Response('{"status":"ok"}', {
				status: 200,
				headers: { 'Content-Type': 'application/json' }
			})
		);
		vi.stubGlobal('fetch', fetchMock);

		const event = makeEvent('/api/health');
		const response = await handle({ event, resolve: vi.fn() } as Parameters<typeof handle>[0]);

		expect(response.status).toBe(200);
		expect(fetchMock).toHaveBeenCalledOnce();
		const [url, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('http://localhost:8400/api/health');
		expect((opts.headers as Headers).get('authorization')).toBe('Bearer test-hook-token');
	});

	it('uses APTL_API_URL when set', async () => {
		mockEnv.APTL_API_URL = 'http://custom-host:9000';
		const fetchMock = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }));
		vi.stubGlobal('fetch', fetchMock);

		const event = makeEvent('/api/health');
		await handle({ event, resolve: vi.fn() } as Parameters<typeof handle>[0]);

		const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toContain('custom-host:9000');
	});

	it('returns 503 when APTL_API_TOKEN is not configured', async () => {
		mockEnv.APTL_API_TOKEN = undefined;

		const event = makeEvent('/api/health');
		const response = await handle({ event, resolve: vi.fn() } as Parameters<typeof handle>[0]);

		expect(response.status).toBe(503);
		const body = await response.json();
		expect(body.detail).toMatch(/not configured/i);
	});

	it('returns 502 when the upstream fetch throws', async () => {
		vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));

		const event = makeEvent('/api/health');
		const response = await handle({ event, resolve: vi.fn() } as Parameters<typeof handle>[0]);

		expect(response.status).toBe(502);
		const body = await response.json();
		expect(body.detail).toMatch(/proxy error/i);
	});

	it('calls resolve() for non-API routes', async () => {
		const resolve = vi.fn().mockResolvedValue(new Response('home page', { status: 200 }));
		const event = makeEvent('/');

		const response = await handle({ event, resolve } as Parameters<typeof handle>[0]);

		expect(resolve).toHaveBeenCalledWith(event);
		expect(response.status).toBe(200);
	});

	it.each([
		['/api/lab/start'],
		['/api/lab/stop'],
		['/api/lab/kill?containers=true']
	])('rejects cross-origin POST %s without upstream fetch', async (pathname) => {
		const fetchMock = vi.fn();
		vi.stubGlobal('fetch', fetchMock);

		const event = makeEvent(pathname, 'POST', {
			Origin: 'https://attacker.example'
		});
		const response = await handle({ event, resolve: vi.fn() } as Parameters<typeof handle>[0]);

		expect(response.status).toBe(403);
		expect(fetchMock).not.toHaveBeenCalled();
		const body = await response.json();
		expect(body.detail).toMatch(/cross-origin/i);
	});

	it('rejects mutating requests with Sec-Fetch-Site: cross-site', async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal('fetch', fetchMock);

		const event = makeEvent('/api/lab/start', 'POST', {
			'Sec-Fetch-Site': 'cross-site'
		});
		const response = await handle({ event, resolve: vi.fn() } as Parameters<typeof handle>[0]);

		expect(response.status).toBe(403);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('allows same-origin POST with matching Origin', async () => {
		const fetchMock = vi.fn().mockResolvedValue(
			new Response('{"status":"ok"}', {
				status: 200,
				headers: { 'Content-Type': 'application/json' }
			})
		);
		vi.stubGlobal('fetch', fetchMock);

		const event = makeEvent('/api/lab/start', 'POST', {
			Origin: 'http://localhost',
			'Sec-Fetch-Site': 'same-origin'
		});
		const response = await handle({ event, resolve: vi.fn() } as Parameters<typeof handle>[0]);

		expect(response.status).toBe(200);
		expect(fetchMock).toHaveBeenCalledOnce();
		const [, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect((opts.headers as Headers).get('authorization')).toBe('Bearer test-hook-token');
	});
});
