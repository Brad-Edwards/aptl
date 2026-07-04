import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

/**
 * Build a minimal fetch Response whose body streams the given SSE chunks, for
 * testing the fetch-based subscribeLabEvents (which replaced EventSource so the
 * stream can carry the X-APTL-Session auth header).
 */
function sseResponse(chunks: string[]) {
	let i = 0;
	const encoder = new TextEncoder();
	return {
		ok: true,
		body: {
			getReader() {
				return {
					read() {
						if (i < chunks.length) {
							return Promise.resolve({ value: encoder.encode(chunks[i++]), done: false });
						}
						return Promise.resolve({ value: undefined, done: true });
					},
					cancel() {}
				};
			}
		}
	};
}

import {
	getLabStatus,
	startLab,
	stopLab,
	killLab,
	getScenarios,
	getScenario,
	getConfig,
	subscribeLabEvents
} from '../../src/lib/api';

describe('API client', () => {
	beforeEach(() => {
		mockFetch.mockReset();
		sessionStorage.clear();
	});

	it('getLabStatus fetches /api/lab/status', async () => {
		const data = { running: true, containers: [], error: null };
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await getLabStatus();
		expect(result).toEqual(data);
		expect(mockFetch).toHaveBeenCalledWith(
			'/api/lab/status',
			expect.objectContaining({ headers: expect.any(Headers) })
		);
	});

	it('startLab posts to /api/lab/start', async () => {
		const data = { success: true, message: 'started', error: null };
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await startLab();
		expect(result).toEqual(data);
		expect(mockFetch).toHaveBeenCalledWith(
			'/api/lab/start',
			expect.objectContaining({ method: 'POST', headers: expect.any(Headers) })
		);
	});

	it('stopLab posts to /api/lab/stop', async () => {
		const data = { success: true, message: 'stopped', error: null };
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await stopLab();
		expect(result).toEqual(data);
		expect(mockFetch).toHaveBeenCalledWith(
			'/api/lab/stop',
			expect.objectContaining({ method: 'POST', headers: expect.any(Headers) })
		);
	});

	it('killLab posts to /api/lab/kill without stopping containers by default', async () => {
		const data = {
			success: true,
			mcp_processes_killed: 3,
			containers_stopped: false,
			session_cleared: true,
			errors: []
		};
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await killLab(false);
		expect(result).toEqual(data);
		expect(mockFetch).toHaveBeenCalledWith(
			'/api/lab/kill?containers=false',
			expect.objectContaining({ method: 'POST', headers: expect.any(Headers) })
		);
	});

	it('killLab passes containers=true to widen the blast radius', async () => {
		const data = {
			success: true,
			mcp_processes_killed: 1,
			containers_stopped: true,
			session_cleared: true,
			errors: []
		};
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await killLab(true);
		expect(result.containers_stopped).toBe(true);
		expect(mockFetch).toHaveBeenCalledWith(
			'/api/lab/kill?containers=true',
			expect.objectContaining({ method: 'POST', headers: expect.any(Headers) })
		);
	});

	it('killLab carries the session header', async () => {
		sessionStorage.setItem('aptl_session', 'tok-kill');
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve({ success: true })
		});

		await killLab(false);
		const headers = mockFetch.mock.calls[0][1].headers as Headers;
		expect(headers.get('X-APTL-Session')).toBe('tok-kill');
	});

	it('startLab carries ADR-030 outcome + diagnostics through fetch', async () => {
		// API now returns the structured partial-readiness fields per ADR-030.
		// Older callers see only success/message/error; new callers can read
		// the outcome string ("ready" | "degraded_usable" | …) and the per-
		// step diagnostic rows. The interface marks both as optional so the
		// fetch boundary keeps round-tripping whatever the server sent.
		const data = {
			success: true,
			message: 'Lab started with outcome=degraded_unusable',
			error: null,
			outcome: 'degraded_unusable',
			diagnostics: [
				{
					step: 'test_ssh',
					component: 'ssh:kali',
					impact: 'readiness',
					severity: 'warning',
					message: 'SSH to kali not ready after 60s',
					operator_action: 'Check kali container sshd'
				},
				{
					step: 'wait_for_services',
					component: 'wazuh_indexer',
					impact: 'telemetry',
					severity: 'warning',
					message: 'Indexer did not become ready within 300s',
					operator_action: ''
				}
			]
		};
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(data)
		});

		const result = await startLab();
		expect(result).toEqual(data);
		expect(result.outcome).toBe('degraded_unusable');
		expect(result.diagnostics?.length).toBe(2);
		expect(result.diagnostics?.[0].impact).toBe('readiness');
		expect(result.diagnostics?.[0].component).toBe('ssh:kali');
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
		expect(mockFetch).toHaveBeenCalledWith(
			'/api/scenarios/test-scenario',
			expect.objectContaining({ headers: expect.any(Headers) })
		);
	});

	it('getScenario encodes the scenario ID', async () => {
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve({})
		});

		await getScenario('has spaces/slashes');
		expect(mockFetch).toHaveBeenCalledWith(
			'/api/scenarios/has%20spaces%2Fslashes',
			expect.objectContaining({ headers: expect.any(Headers) })
		);
	});

	it('attaches the X-APTL-Session header when a session token is stored', async () => {
		sessionStorage.setItem('aptl_session', 'tok-123');
		mockFetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({}) });

		await getConfig();

		const headers = mockFetch.mock.calls[0][1].headers as Headers;
		expect(headers.get('X-APTL-Session')).toBe('tok-123');
	});

	it('omits the X-APTL-Session header when no token is stored', async () => {
		mockFetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({}) });

		await getConfig();

		const headers = mockFetch.mock.calls[0][1].headers as Headers;
		expect(headers.has('X-APTL-Session')).toBe(false);
	});

	it('subscribeLabEvents streams lab_status events to onMessage', async () => {
		const status = { running: true, containers: [], error: null };
		mockFetch.mockResolvedValueOnce(
			sseResponse([`event: lab_status\ndata: ${JSON.stringify(status)}\n\n`])
		);
		const onMessage = vi.fn();

		const sub = subscribeLabEvents(onMessage);
		await vi.waitFor(() => expect(onMessage).toHaveBeenCalledWith(status));
		sub.close();
	});

	it('subscribeLabEvents carries the session header on the stream request', async () => {
		sessionStorage.setItem('aptl_session', 'tok-sse');
		mockFetch.mockResolvedValueOnce(sseResponse([]));

		const sub = subscribeLabEvents(vi.fn());
		await vi.waitFor(() => expect(mockFetch).toHaveBeenCalled());
		const headers = mockFetch.mock.calls[0][1].headers as Headers;
		expect(headers.get('X-APTL-Session')).toBe('tok-sse');
		sub.close();
	});

	it('subscribeLabEvents calls onError when the stream ends', async () => {
		mockFetch.mockResolvedValueOnce(sseResponse([]));
		const onError = vi.fn();

		const sub = subscribeLabEvents(vi.fn(), onError);
		await vi.waitFor(() => expect(onError).toHaveBeenCalled());
		sub.close();
	});

	it('subscribeLabEvents does not call onError after an explicit close', async () => {
		let resolveRead: (v: { value: undefined; done: boolean }) => void = () => {};
		const reader = {
			read: vi.fn(() => new Promise((r) => (resolveRead = r))),
			cancel: vi.fn()
		};
		mockFetch.mockResolvedValueOnce({ ok: true, body: { getReader: () => reader } });
		const onError = vi.fn();

		const sub = subscribeLabEvents(vi.fn(), onError);
		await vi.waitFor(() => expect(reader.read).toHaveBeenCalled());
		sub.close();
		// Resolve the pending read as stream-end AFTER close; onError must stay silent.
		resolveRead({ value: undefined, done: true });
		await Promise.resolve();
		expect(onError).not.toHaveBeenCalled();
	});
});
