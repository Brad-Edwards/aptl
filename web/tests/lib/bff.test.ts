/**
 * Unit tests for the BFF helper module (ADR-039 single-origin terminal flow).
 *
 * terminalWsUrl: derives same-origin WS URL from window.location (never a
 * hardcoded host). fetchTerminalTicket: calls the relative ticket endpoint
 * and returns the opaque ticket string; throws on non-ok response.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { terminalWsUrl, fetchTerminalTicket } from '../../src/lib/bff';

// Helper: override window.location in jsdom for the duration of a test.
function stubLocation(protocol: string, host: string) {
	vi.stubGlobal('location', { protocol, host });
}

describe('terminalWsUrl', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('returns a ws: URL for http pages', () => {
		stubLocation('http:', 'localhost:5173');
		expect(terminalWsUrl('kali')).toBe('ws://localhost:5173/api/terminal/ws/kali');
	});

	it('returns a wss: URL for https pages', () => {
		stubLocation('https:', 'aptl.example.com');
		expect(terminalWsUrl('kali')).toBe('wss://aptl.example.com/api/terminal/ws/kali');
	});

	it('includes the container name in the URL path', () => {
		stubLocation('http:', 'localhost:5173');
		expect(terminalWsUrl('metasploitable')).toContain('/api/terminal/ws/metasploitable');
	});

	it('derives host from window.location.host, not a hardcoded value', () => {
		stubLocation('http:', 'my-custom-host:9999');
		const url = terminalWsUrl('kali');
		expect(url).toContain('my-custom-host:9999');
		expect(url).not.toContain('localhost:8400');
		expect(url).not.toContain('127.0.0.1:8400');
	});
});

describe('fetchTerminalTicket', () => {
	afterEach(() => {
		vi.restoreAllMocks();
		vi.unstubAllGlobals();
	});

	it('calls /api/terminal/ticket with a relative path and the session header', async () => {
		sessionStorage.setItem('aptl_session', 'tok-ws');
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue({
				ok: true,
				json: () => Promise.resolve({ ticket: 'abc123', expires_in: 30 })
			})
		);

		await fetchTerminalTicket();
		expect(fetch).toHaveBeenCalledWith(
			'/api/terminal/ticket',
			expect.objectContaining({ headers: expect.any(Headers) })
		);
		const headers = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][1].headers as Headers;
		expect(headers.get('X-APTL-Session')).toBe('tok-ws');
		sessionStorage.removeItem('aptl_session');
	});

	it('returns the ticket string from the response', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue({
				ok: true,
				json: () => Promise.resolve({ ticket: 'test-ticket-xyz', expires_in: 30 })
			})
		);

		const ticket = await fetchTerminalTicket();
		expect(ticket).toBe('test-ticket-xyz');
	});

	it('throws on a non-ok response without leaking server details', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue({
				ok: false,
				status: 503
			})
		);

		await expect(fetchTerminalTicket()).rejects.toThrow();
	});
});
