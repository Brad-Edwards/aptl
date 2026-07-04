import { describe, it, expect, vi, beforeEach } from 'vitest';
import { get } from 'svelte/store';

// The lab store now drives SSE through `fetch` streaming (not EventSource), so
// the X-APTL-Session auth header can ride the request. This harness serves
// /api/lab/status as JSON and /api/lab/events as a controllable SSE stream,
// recording each events connection's AbortSignal + push/end handles.

interface EventsConn {
	signal?: AbortSignal;
	push(chunk: string): void;
	end(): void;
}

let eventsConns: EventsConn[];
let statusResponder: () => Promise<unknown>;

function buildEventsResponse(init: RequestInit | undefined): { conn: EventsConn; res: unknown } {
	const queue: string[] = [];
	let notify: (() => void) | null = null;
	let ended = false;
	const encoder = new TextEncoder();

	const wake = () => {
		const n = notify;
		notify = null;
		n?.();
	};
	const conn: EventsConn = {
		signal: init?.signal ?? undefined,
		push(chunk) {
			queue.push(chunk);
			wake();
		},
		end() {
			ended = true;
			wake();
		}
	};
	const reader = {
		read(): Promise<{ value?: Uint8Array; done: boolean }> {
			if (queue.length) return Promise.resolve({ value: encoder.encode(queue.shift()!), done: false });
			if (ended) return Promise.resolve({ done: true });
			return new Promise((resolve) => {
				notify = () => {
					if (queue.length) resolve({ value: encoder.encode(queue.shift()!), done: false });
					else resolve({ done: true });
				};
			});
		},
		cancel() {
			ended = true;
		}
	};
	return { conn, res: { ok: true, body: { getReader: () => reader } } };
}

const mockFetch = vi.fn((url: string, init?: RequestInit) => {
	if (typeof url === 'string' && url.includes('/lab/events')) {
		const { conn, res } = buildEventsResponse(init);
		eventsConns.push(conn);
		return Promise.resolve(res);
	}
	return statusResponder();
});
vi.stubGlobal('fetch', mockFetch);

describe('lab store', () => {
	beforeEach(() => {
		mockFetch.mockClear();
		eventsConns = [];
		statusResponder = () =>
			Promise.resolve({
				ok: true,
				json: () => Promise.resolve({ running: false, containers: [], error: null })
			});
	});

	it('initLabStore fetches status and sets store', async () => {
		statusResponder = () =>
			Promise.resolve({
				ok: true,
				json: () => Promise.resolve({ running: true, containers: [], error: null })
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
		statusResponder = () => Promise.reject(new Error('Network error'));

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

	it('destroyLabStore aborts the SSE stream', async () => {
		const { initLabStore, destroyLabStore } = await import('../../src/lib/stores/lab');

		initLabStore();
		await vi.waitFor(() => expect(eventsConns.length).toBe(1));

		destroyLabStore();
		expect(eventsConns[0].signal?.aborted).toBe(true);
	});

	it('SSE message updates lab status store', async () => {
		const { labStatus, initLabStore, destroyLabStore } = await import(
			'../../src/lib/stores/lab'
		);

		initLabStore();
		await vi.waitFor(() => expect(eventsConns.length).toBe(1));

		const sseData = {
			running: true,
			containers: [
				{ name: 'kali', state: 'running', status: '', health: '', image: '', ports: [] }
			],
			error: null
		};
		eventsConns[0].push(`event: lab_status\ndata: ${JSON.stringify(sseData)}\n\n`);

		await vi.waitFor(() => expect(get(labStatus).running).toBe(true));
		expect(get(labStatus).containers).toHaveLength(1);

		destroyLabStore();
	});

	it('schedules a reconnect when the stream ends', async () => {
		const { initLabStore, destroyLabStore } = await import('../../src/lib/stores/lab');

		initLabStore();
		await vi.waitFor(() => expect(eventsConns.length).toBe(1));

		vi.useFakeTimers();
		try {
			eventsConns[0].end(); // stream end → onError → setTimeout(reconnect)
			await vi.advanceTimersByTimeAsync(5500);
			// Reconnect re-ran initLabStore, opening a second events connection.
			expect(eventsConns.length).toBeGreaterThan(1);
		} finally {
			vi.useRealTimers();
		}

		destroyLabStore();
	});

	it('reinitializing aborts the previous stream', async () => {
		const { initLabStore, destroyLabStore } = await import('../../src/lib/stores/lab');

		initLabStore();
		await vi.waitFor(() => expect(eventsConns.length).toBe(1));

		initLabStore();
		await vi.waitFor(() => expect(eventsConns.length).toBe(2));

		expect(eventsConns[0].signal?.aborted).toBe(true);

		destroyLabStore();
	});

	it('refreshLabStatus re-fetches status without opening an SSE stream', async () => {
		statusResponder = () =>
			Promise.resolve({
				ok: true,
				json: () => Promise.resolve({ running: true, containers: [], error: null })
			});

		const { labStatus, refreshLabStatus } = await import('../../src/lib/stores/lab');

		await refreshLabStatus();

		expect(get(labStatus).running).toBe(true);
		// A status refresh must not spin up a new events subscription.
		expect(eventsConns.length).toBe(0);
	});

	it('refreshLabStatus records a fetch error on the store', async () => {
		statusResponder = () => Promise.reject(new Error('refresh boom'));

		const { labStatus, refreshLabStatus } = await import('../../src/lib/stores/lab');

		await refreshLabStatus();

		expect(get(labStatus).error).toContain('refresh boom');
	});

	it('destroyLabStore is safe to call when no stream exists', async () => {
		const { destroyLabStore } = await import('../../src/lib/stores/lab');

		// Tearing down with no active stream (and again, idempotently) must not throw.
		expect(() => {
			destroyLabStore();
			destroyLabStore();
		}).not.toThrow();
	});
});
