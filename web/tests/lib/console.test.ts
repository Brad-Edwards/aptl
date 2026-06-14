import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import { drainRecords, getState, createSession, streamMessage } from '../../src/lib/console/api';
import type { StreamEvent } from '../../src/lib/console/types';

describe('drainRecords (SSE parser)', () => {
	it('parses a single complete record and keeps the tail', () => {
		const events: StreamEvent[] = [];
		const tail = drainRecords(
			'event: token\ndata: {"type":"token","text":"hi"}\n\nevent: end\ndata: {"type":"end"}',
			(e) => events.push(e)
		);
		expect(events).toHaveLength(1);
		expect(events[0]).toEqual({ type: 'token', text: 'hi' });
		// The incomplete second record is returned unconsumed.
		expect(tail).toContain('end');
	});

	it('ignores malformed JSON records', () => {
		const events: StreamEvent[] = [];
		drainRecords('data: not json\n\n', (e) => events.push(e));
		expect(events).toHaveLength(0);
	});

	it('handles multiple records in one buffer', () => {
		const events: StreamEvent[] = [];
		drainRecords(
			'data: {"type":"token","text":"a"}\n\ndata: {"type":"token","text":"b"}\n\n',
			(e) => events.push(e)
		);
		expect(events.map((e) => (e.type === 'token' ? e.text : ''))).toEqual(['a', 'b']);
	});
});

describe('console API client', () => {
	beforeEach(() => mockFetch.mockReset());

	it('getState hits /api/console/state', async () => {
		mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({ sessions: [] }) });
		await getState();
		expect(mockFetch).toHaveBeenCalledWith('/api/console/state', expect.any(Object));
	});

	it('createSession posts JSON body', async () => {
		mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({ id: 'sess_1' }) });
		await createSession({ role: 'red' });
		const [url, init] = mockFetch.mock.calls[0];
		expect(url).toBe('/api/console/sessions');
		expect(init.method).toBe('POST');
		expect(JSON.parse(init.body)).toEqual({ role: 'red' });
	});

	it('streamMessage reads and parses the response stream', async () => {
		const chunks = [
			'data: {"type":"token","text":"hello"}\n\n',
			'data: {"type":"end"}\n\n'
		].map((s) => new TextEncoder().encode(s));
		let i = 0;
		const reader = {
			read: async () =>
				i < chunks.length ? { value: chunks[i++], done: false } : { value: undefined, done: true }
		};
		mockFetch.mockResolvedValueOnce({ ok: true, body: { getReader: () => reader } });

		const events: StreamEvent[] = [];
		await streamMessage('sess_1', 'hi', (e) => events.push(e));
		expect(events.map((e) => e.type)).toContain('token');
		expect(events.map((e) => e.type)).toContain('end');
	});
});
