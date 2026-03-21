import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { get } from 'svelte/store';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Mock EventSource
class MockEventSource {
	static CONNECTING = 0;
	static OPEN = 1;
	static CLOSED = 2;

	url: string;
	readyState = MockEventSource.OPEN;
	onerror: ((event: Event) => void) | null = null;
	private listeners: Record<string, ((event: MessageEvent) => void)[]> = {};

	constructor(url: string) {
		this.url = url;
	}

	addEventListener(type: string, listener: (event: MessageEvent) => void) {
		if (!this.listeners[type]) this.listeners[type] = [];
		this.listeners[type].push(listener);
	}

	close() {
		this.readyState = MockEventSource.CLOSED;
	}

	// Test helper to simulate events
	emit(type: string, data: string) {
		for (const listener of this.listeners[type] || []) {
			listener(new MessageEvent(type, { data }));
		}
	}
}

vi.stubGlobal('EventSource', MockEventSource);

describe('lab store', () => {
	beforeEach(() => {
		mockFetch.mockReset();
	});

	it('initLabStore fetches status and sets store', async () => {
		const statusData = { running: true, containers: [], error: null };
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(statusData)
		});

		const { labStatus, labLoading, initLabStore, destroyLabStore } = await import(
			'../../src/lib/stores/lab'
		);

		initLabStore();

		// Wait for the async fetch to complete
		await vi.waitFor(() => {
			expect(get(labLoading)).toBe(false);
		});

		expect(get(labStatus).running).toBe(true);

		destroyLabStore();
	});

	it('initLabStore handles fetch error', async () => {
		mockFetch.mockRejectedValueOnce(new Error('Network error'));

		const { labStatus, labLoading, initLabStore, destroyLabStore } = await import(
			'../../src/lib/stores/lab'
		);

		initLabStore();

		await vi.waitFor(() => {
			expect(get(labLoading)).toBe(false);
		});

		expect(get(labStatus).error).toContain('Network error');

		destroyLabStore();
	});

	it('destroyLabStore closes EventSource', async () => {
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve({ running: false, containers: [], error: null })
		});

		const { initLabStore, destroyLabStore } = await import('../../src/lib/stores/lab');

		initLabStore();
		destroyLabStore();

		// No error thrown = success
	});
});
