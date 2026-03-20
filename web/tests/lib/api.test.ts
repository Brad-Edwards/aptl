import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import { getLabStatus, startLab, stopLab, getScenarios, getConfig } from '../../src/lib/api';

describe('API client', () => {
	beforeEach(() => {
		mockFetch.mockReset();
	});

	it('getLabStatus fetches /api/lab/status', async () => {
		const data = { running: true, containers: [], error: '' };
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await getLabStatus();
		expect(result).toEqual(data);
		expect(mockFetch).toHaveBeenCalledWith('/api/lab/status', undefined);
	});

	it('startLab posts to /api/lab/start', async () => {
		const data = { success: true, message: 'started', error: '' };
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await startLab();
		expect(result).toEqual(data);
		expect(mockFetch).toHaveBeenCalledWith('/api/lab/start', { method: 'POST' });
	});

	it('stopLab posts to /api/lab/stop', async () => {
		const data = { success: true, message: 'stopped', error: '' };
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await stopLab();
		expect(result).toEqual(data);
		expect(mockFetch).toHaveBeenCalledWith('/api/lab/stop', { method: 'POST' });
	});

	it('getScenarios fetches /api/scenarios', async () => {
		const data = [{ id: 'test', name: 'Test' }];
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await getScenarios();
		expect(result).toEqual(data);
	});

	it('getConfig fetches /api/config', async () => {
		const data = { lab_name: 'aptl', containers: {} };
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await getConfig();
		expect(result).toEqual(data);
	});

	it('throws on non-ok response', async () => {
		mockFetch.mockResolvedValueOnce({
			ok: false,
			status: 500,
			text: () => Promise.resolve('Internal Server Error')
		});

		await expect(getLabStatus()).rejects.toThrow('API error 500');
	});
});
