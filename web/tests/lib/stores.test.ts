import { describe, it, expect, vi, beforeEach } from 'vitest';
import { get } from 'svelte/store';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Track MockEventSource instances for test access
const esInstances: MockEventSource[] = [];

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
		esInstances.push(this);
	}

	addEventListener(type: string, listener: (event: MessageEvent) => void) {
		if (!this.listeners[type]) this.listeners[type] = [];
		this.listeners[type].push(listener);
	}

	close() {
		this.readyState = MockEventSource.CLOSED;
	}

	// Test helper: simulate an SSE event
	emit(type: string, data: string) {
		for (const listener of this.listeners[type] || []) {
			listener(new MessageEvent(type, { data }));
		}
	}

	// Test helper: simulate an error event
	triggerError() {
		if (this.onerror) {
			const event = new Event('error');
			Object.defineProperty(event, 'target', { value: this });
			this.onerror(event);
		}
	}
}

vi.stubGlobal('EventSource', MockEventSource);

describe('lab store', () => {
	beforeEach(() => {
		mockFetch.mockReset();
		esInstances.length = 0;
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
	});

	it('SSE message updates lab status store', async () => {
		const initialData = { running: false, containers: [], error: null };
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(initialData)
		});

		const { labStatus, initLabStore, destroyLabStore } = await import(
			'../../src/lib/stores/lab'
		);

		initLabStore();

		await vi.waitFor(() => {
			expect(get(labStatus).error).toBeNull();
		});

		// Get the MockEventSource created by subscribeLabEvents
		const es = esInstances[esInstances.length - 1];
		expect(es).toBeDefined();

		// Simulate an SSE lab_status event
		const sseData = {
			running: true,
			containers: [{ name: 'kali', state: 'running', status: '', health: '', image: '', ports: [] }],
			error: null
		};
		es.emit('lab_status', JSON.stringify(sseData));

		expect(get(labStatus).running).toBe(true);
		expect(get(labStatus).containers).toHaveLength(1);

		destroyLabStore();
	});

	it('SSE error with CLOSED readyState schedules reconnect', async () => {
		vi.useFakeTimers();

		mockFetch.mockResolvedValue({
			ok: true,
			json: () => Promise.resolve({ running: false, containers: [], error: null })
		});

		const { initLabStore, destroyLabStore } = await import('../../src/lib/stores/lab');

		initLabStore();

		await vi.waitFor(() => {
			expect(esInstances.length).toBeGreaterThan(0);
		});

		const es = esInstances[esInstances.length - 1];
		// Simulate connection closed then error
		es.readyState = MockEventSource.CLOSED;
		es.triggerError();

		const countBefore = esInstances.length;

		// Advance past the reconnect delay (5000ms)
		await vi.advanceTimersByTimeAsync(5500);

		// A new EventSource should have been created by the reconnect
		expect(esInstances.length).toBeGreaterThan(countBefore);

		destroyLabStore();
		vi.useRealTimers();
	});

	it('reinitializing closes previous EventSource', async () => {
		mockFetch.mockResolvedValue({
			ok: true,
			json: () => Promise.resolve({ running: false, containers: [], error: null })
		});

		const { initLabStore, destroyLabStore } = await import('../../src/lib/stores/lab');

		initLabStore();
		const firstEs = esInstances[esInstances.length - 1];

		initLabStore();

		// First EventSource should have been closed
		expect(firstEs.readyState).toBe(MockEventSource.CLOSED);

		destroyLabStore();
	});

	it('destroyLabStore is safe to call when no EventSource exists', async () => {
		const { destroyLabStore } = await import('../../src/lib/stores/lab');

		// Should not throw
		destroyLabStore();
		destroyLabStore();
	});
});
