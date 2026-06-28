/**
 * Unit tests for Terminal.svelte — single-origin BFF flow.
 *
 * The component must:
 *  1. Fetch a short-lived ticket from /api/terminal/ticket (relative path,
 *     no Authorization header, no hardcoded host).
 *  2. Build the WS URL from window.location, not a hardcoded API host.
 *  3. Open the WS with the aptl-token.<ticket> subprotocol.
 *  4. Write a terminal error and skip WS if the ticket fetch fails.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render } from '@testing-library/svelte';
import Terminal from '../../src/lib/components/Terminal.svelte';

// Stub heavy DOM-canvas dependencies that jsdom cannot handle.
vi.mock('@xterm/xterm', () => ({
	Terminal: vi.fn(() => ({
		loadAddon: vi.fn(),
		open: vi.fn(),
		onData: vi.fn(),
		onResize: vi.fn(),
		write: vi.fn(),
		dispose: vi.fn(),
		cols: 80,
		rows: 24
	}))
}));

vi.mock('@xterm/addon-fit', () => ({
	FitAddon: vi.fn(() => ({ fit: vi.fn(), dispose: vi.fn() }))
}));

vi.mock('@xterm/addon-web-links', () => ({
	WebLinksAddon: vi.fn(() => ({ dispose: vi.fn() }))
}));

vi.mock('@xterm/xterm/css/xterm.css', () => ({}));

const TICKET = 'test-ticket-xyz';

describe('Terminal', () => {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	let WSSpy: ReturnType<typeof vi.fn>;
	let fetchMock: ReturnType<typeof vi.fn>;

	beforeEach(() => {
		WSSpy = vi.fn(function (this: Record<string, unknown>) {
			// Provide the full interface the component uses on the ws instance.
			this.readyState = 0; // CONNECTING
			this.close = vi.fn();
			this.send = vi.fn();
			this.onopen = null;
			this.onmessage = null;
			this.onclose = null;
			this.onerror = null;
		});
		Object.assign(WSSpy, { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 });
		vi.stubGlobal('WebSocket', WSSpy);
		vi.stubGlobal('ResizeObserver', vi.fn(() => ({ observe: vi.fn(), disconnect: vi.fn() })));

		// Default: ticket fetch succeeds.
		fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			json: () => Promise.resolve({ ticket: TICKET, expires_in: 30 })
		});
		vi.stubGlobal('fetch', fetchMock);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('fetches a ticket from /api/terminal/ticket before opening the WS', async () => {
		render(Terminal, { props: { container: 'kali' } });
		await new Promise((r) => setTimeout(r, 0));

		expect(fetchMock).toHaveBeenCalledWith(
			'/api/terminal/ticket',
			expect.objectContaining({ headers: expect.any(Headers) })
		);
	});

	it('constructs WS URL from window.location, not a hardcoded API host', async () => {
		render(Terminal, { props: { container: 'kali' } });
		await new Promise((r) => setTimeout(r, 0));

		expect(WSSpy).toHaveBeenCalledOnce();
		const url: string = WSSpy.mock.calls[0][0];
		// Must be a valid same-origin WS URL
		expect(url).toMatch(/^wss?:\/\//);
		expect(url).toContain('/api/terminal/ws/kali');
		// Must NOT use any hardcoded API host
		expect(url).not.toContain('localhost:8400');
		expect(url).not.toContain('127.0.0.1:8400');
	});

	it('passes aptl-token.<ticket> subprotocol from the ticket endpoint', async () => {
		render(Terminal, { props: { container: 'kali' } });
		await new Promise((r) => setTimeout(r, 0));

		const protocols: string[] = WSSpy.mock.calls[0][1];
		expect(protocols).toEqual([`aptl-token.${TICKET}`]);
	});

	it('encodes the container name in the WS path', async () => {
		render(Terminal, { props: { container: 'metasploitable' } });
		await new Promise((r) => setTimeout(r, 0));

		const url: string = WSSpy.mock.calls[0][0];
		expect(url).toContain('/api/terminal/ws/metasploitable');
	});

	it('does not open WS when ticket fetch fails', async () => {
		fetchMock.mockResolvedValue({ ok: false, status: 503 });

		render(Terminal, { props: { container: 'kali' } });
		await new Promise((r) => setTimeout(r, 0));

		expect(WSSpy).not.toHaveBeenCalled();
	});

	it('does not open an orphan WS if torn down during ticket fetch', async () => {
		// Hold the ticket request in flight, tear the component down, THEN resolve.
		let resolveTicket!: () => void;
		fetchMock.mockReturnValue(
			new Promise((res) => {
				resolveTicket = () =>
					res({ ok: true, json: () => Promise.resolve({ ticket: TICKET, expires_in: 30 }) });
			})
		);

		const { unmount } = render(Terminal, { props: { container: 'kali' } });
		await new Promise((r) => setTimeout(r, 0));
		unmount(); // teardown while the ticket fetch is still pending
		resolveTicket();
		await new Promise((r) => setTimeout(r, 0));

		// The destroyed guard must prevent opening a socket the component can no
		// longer manage.
		expect(WSSpy).not.toHaveBeenCalled();
	});
});
