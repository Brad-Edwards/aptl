/**
 * Unit tests for the BFF helper module (ADR-039 single-origin terminal flow).
 *
 * terminalWsUrl: derives same-origin WS URL from window.location (never a
 * hardcoded host). fetchTerminalTicket: calls the relative ticket endpoint
 * and returns the opaque ticket string; throws on non-ok response.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import {
	terminalWsUrl,
	fetchTerminalTicket,
	TerminalTicketError,
	describeTicketFailure,
	describeErrorFrame,
	describeTerminalClose
} from '../../src/lib/bff';

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

	it('throws a TerminalTicketError carrying the HTTP status', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue({
				ok: false,
				status: 401
			})
		);

		await expect(fetchTerminalTicket()).rejects.toBeInstanceOf(TerminalTicketError);
		await fetchTerminalTicket().catch((err) => {
			expect(err).toBeInstanceOf(TerminalTicketError);
			expect(err.status).toBe(401);
			// No server body is echoed into the error message.
			expect(err.message).not.toMatch(/detail|body|stack/i);
		});
	});
});

describe('describeTicketFailure', () => {
	it('maps 401 to an auth/session-expired message', () => {
		expect(describeTicketFailure(401)).toMatch(/not authorized/i);
		expect(describeTicketFailure(401)).toMatch(/session/i);
	});

	it('maps 403 to the same auth category', () => {
		expect(describeTicketFailure(403)).toMatch(/not authorized/i);
	});

	it('maps any other status to a generic start failure', () => {
		expect(describeTicketFailure(503)).toMatch(/could not start/i);
		expect(describeTicketFailure(0)).toMatch(/could not start/i);
	});
});

describe('describeErrorFrame', () => {
	it('surfaces the server error message verbatim as an error status', () => {
		const s = describeErrorFrame('Lab is not running');
		expect(s).toEqual({ phase: 'error', text: 'Lab is not running', isError: true });
	});
});

describe('describeTerminalClose', () => {
	it('maps each narrow server close reason to operator copy', () => {
		expect(describeTerminalClose(1008, 'Unauthorized', false)).toMatchObject({
			phase: 'error',
			isError: true
		});
		expect(describeTerminalClose(1008, 'Origin not allowed', false).text).toMatch(/origin/i);
		expect(describeTerminalClose(1008, 'Unknown container', false).text).toMatch(/allowed/i);
		expect(describeTerminalClose(1008, 'Lab not running', false).text).toMatch(/not running/i);
		expect(describeTerminalClose(1008, 'Container not available', false).text).toMatch(
			/not currently available/i
		);
		expect(describeTerminalClose(1008, 'Host keys not pinned', false).text).toMatch(
			/host keys.*restart/i
		);
	});

	it('surfaces an unmapped but present reason verbatim', () => {
		const s = describeTerminalClose(1008, 'Some new backend reason', false);
		expect(s).toEqual({ phase: 'error', text: 'Some new backend reason', isError: true });
	});

	it('reports an abnormal close with no reason and no data as refused', () => {
		const s = describeTerminalClose(1006, '', false);
		expect(s.phase).toBe('error');
		expect(s.text).toMatch(/refused|unauthorized|blocked/i);
	});

	it('reports a close after data as a graceful session end', () => {
		const s = describeTerminalClose(1000, '', true);
		expect(s.phase).toBe('closed');
		expect(s.isError).toBe(false);
		expect(s.text).toMatch(/ended/i);
	});

	it('reports a normal close with no data as a plain closed state', () => {
		const s = describeTerminalClose(1000, '', false);
		expect(s.phase).toBe('closed');
		expect(s.isError).toBe(false);
	});
});
