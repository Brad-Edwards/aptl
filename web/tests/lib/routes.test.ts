import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('scenario [id] page load', () => {
	// `load` routes through `getScenario()` (shared API boundary, carries the
	// X-APTL-Session header) and threads its load-provided `event.fetch` into it,
	// so these assert the mock fetch is the one used to reach `/api/scenarios/:id`.
	it('fetches scenario by ID and returns it', async () => {
		const scenarioData = {
			id: 'test-1',
			name: 'Test',
			description: '',
			blocks: []
		};
		const mockFetch = vi.fn().mockResolvedValue({
			ok: true,
			json: () => Promise.resolve(scenarioData)
		});

		const { load } = await import('../../src/routes/scenarios/[id]/+page');
		const result = await load({
			params: { id: 'test-1' },
			fetch: mockFetch
		} as any);

		expect(result.scenario).toEqual(scenarioData);
		expect(mockFetch).toHaveBeenCalledWith(
			'/api/scenarios/test-1',
			expect.objectContaining({ headers: expect.any(Headers) })
		);
	});

	it('encodes special characters in scenario ID', async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			ok: true,
			json: () => Promise.resolve({ id: 'a/b', blocks: [] })
		});

		const { load } = await import('../../src/routes/scenarios/[id]/+page');
		await load({ params: { id: 'a/b' }, fetch: mockFetch } as any);

		expect(mockFetch).toHaveBeenCalledWith(
			'/api/scenarios/a%2Fb',
			expect.objectContaining({ headers: expect.any(Headers) })
		);
	});

	it('maps an unknown scenario (404) to a route-level not-found', async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			ok: false,
			status: 404,
			text: () => Promise.resolve('Unknown scenario')
		});

		const { load } = await import('../../src/routes/scenarios/[id]/+page');

		await expect(
			load({ params: { id: 'missing' }, fetch: mockFetch } as any)
		).rejects.toMatchObject({
			status: 404,
			body: { message: expect.stringContaining('not found') }
		});
	});

	it('maps a projection failure (502) to a redacted unavailable state', async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			ok: false,
			status: 502,
			text: () => Promise.resolve('boom')
		});

		const { load } = await import('../../src/routes/scenarios/[id]/+page');

		await expect(
			load({ params: { id: 'broken' }, fetch: mockFetch } as any)
		).rejects.toMatchObject({
			status: 502,
			body: { message: expect.stringContaining('unavailable') }
		});
	});
});

describe('home page load', () => {
	// `load` routes through `getScenarios()` (shared API boundary, carries the
	// X-APTL-Session header) and threads its load-provided `event.fetch` into it,
	// so these pass a mock `fetch` via the load event and assert it is the one
	// used to reach `/api/scenarios`.
	beforeEach(() => {
		sessionStorage.clear();
	});

	it('fetches and returns the scenario catalog summary', async () => {
		const scenarios = [{ id: 's1', name: 'Scenario 1', description: 'first' }];
		const mockFetch = vi.fn().mockResolvedValue({
			ok: true,
			json: () => Promise.resolve(scenarios)
		});

		const { load } = await import('../../src/routes/+page');
		const result = await load({ fetch: mockFetch } as any);

		expect(result.scenarios).toEqual(scenarios);
		expect(result.scenariosError).toBe(false);
		expect(mockFetch).toHaveBeenCalledWith(
			'/api/scenarios',
			expect.objectContaining({ headers: expect.any(Headers) })
		);
	});

	it('degrades to an empty list with an error flag on fetch error', async () => {
		const mockFetch = vi.fn().mockRejectedValue(new Error('Network error'));

		const { load } = await import('../../src/routes/+page');
		const result = await load({ fetch: mockFetch } as any);

		expect(result.scenarios).toEqual([]);
		expect(result.scenariosError).toBe(true);
	});

	it('degrades to an empty list with an error flag on non-ok response', async () => {
		const mockFetch = vi
			.fn()
			.mockResolvedValue({ ok: false, status: 500, text: () => Promise.resolve('boom') });

		const { load } = await import('../../src/routes/+page');
		const result = await load({ fetch: mockFetch } as any);

		expect(result.scenarios).toEqual([]);
		expect(result.scenariosError).toBe(true);
	});
});
