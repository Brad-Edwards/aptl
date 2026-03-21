import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Mock EventSource for jsdom
class MockEventSource extends EventTarget {
	static CONNECTING = 0;
	static OPEN = 1;
	static CLOSED = 2;

	url: string;
	readyState = MockEventSource.OPEN;
	onerror: ((event: Event) => void) | null = null;

	constructor(url: string) {
		super();
		this.url = url;
	}

	close() {
		this.readyState = MockEventSource.CLOSED;
	}
}
vi.stubGlobal('EventSource', MockEventSource);

import {
	getLabStatus,
	startLab,
	stopLab,
	getScenarios,
	getScenario,
	getConfig,
	subscribeLabEvents
} from '../../src/lib/api';

describe('API client', () => {
	beforeEach(() => {
		mockFetch.mockReset();
	});

	it('getLabStatus fetches /api/lab/status', async () => {
		const data = { running: true, containers: [], error: null };
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await getLabStatus();
		expect(result).toEqual(data);
		expect(mockFetch).toHaveBeenCalledWith('/api/lab/status', undefined);
	});

	it('startLab posts to /api/lab/start', async () => {
		const data = { success: true, message: 'started', error: null };
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await startLab();
		expect(result).toEqual(data);
		expect(mockFetch).toHaveBeenCalledWith('/api/lab/start', { method: 'POST' });
	});

	it('stopLab posts to /api/lab/stop', async () => {
		const data = { success: true, message: 'stopped', error: null };
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

	it('truncates long error text to 500 characters', async () => {
		const longText = 'x'.repeat(1000);
		mockFetch.mockResolvedValueOnce({
			ok: false,
			status: 500,
			text: () => Promise.resolve(longText)
		});

		await expect(getLabStatus()).rejects.toThrow(/\.\.\.$/);
	});

	it('getScenario fetches /api/scenarios/:id', async () => {
		const data = { metadata: { id: 'test-scenario' } };
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await getScenario('test-scenario');
		expect(result).toEqual(data);
		expect(mockFetch).toHaveBeenCalledWith('/api/scenarios/test-scenario', undefined);
	});

	it('getScenario encodes the scenario ID', async () => {
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve({})
		});

		await getScenario('has spaces/slashes');
		expect(mockFetch).toHaveBeenCalledWith(
			'/api/scenarios/has%20spaces%2Fslashes',
			undefined
		);
	});

	it('subscribeLabEvents creates EventSource and relays messages', () => {
		const onMessage = vi.fn();
		const onError = vi.fn();

		const es = subscribeLabEvents(onMessage, onError);

		expect(es).toBeInstanceOf(EventSource);

		// Simulate a lab_status SSE event
		const statusData = { running: true, containers: [], error: null };
		const event = new MessageEvent('lab_status', {
			data: JSON.stringify(statusData)
		});
		es.dispatchEvent(event);

		expect(onMessage).toHaveBeenCalledWith(statusData);

		es.close();
	});

	it('subscribeLabEvents sets onerror handler when provided', () => {
		const onMessage = vi.fn();
		const onError = vi.fn();

		const es = subscribeLabEvents(onMessage, onError);
		expect(es.onerror).toBe(onError);
		es.close();
	});

	it('subscribeLabEvents works without error handler', () => {
		const onMessage = vi.fn();
		const es = subscribeLabEvents(onMessage);
		expect(es.onerror).toBeNull();
		es.close();
	});
});
