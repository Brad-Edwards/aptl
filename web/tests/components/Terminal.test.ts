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

const _TOKEN = 'test-ws-token-abc123';
const _HOST = 'localhost:8400';

function makeCtx(token: string) {
	return new Map([['apiCtx', { apiHost: _HOST, wsToken: token }]]);
}

describe('Terminal', () => {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	let WSSpy: ReturnType<typeof vi.fn>;

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
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('constructs WS URL from apiHost context, not window.location.host', async () => {
		render(Terminal, { props: { container: 'kali' }, context: makeCtx(_TOKEN) });
		await new Promise((r) => setTimeout(r, 0));

		expect(WSSpy).toHaveBeenCalledOnce();
		const url: string = WSSpy.mock.calls[0][0];
		expect(url).toContain(_HOST);
		expect(url).toContain('/api/terminal/ws/kali');
		// Must NOT fall back to window.location.host (which would be '' in jsdom)
		expect(url).not.toBe(`ws://${window.location.host}/api/terminal/ws/kali`);
	});

	it('passes aptl-token.<token> subprotocol when wsToken is set', async () => {
		render(Terminal, { props: { container: 'kali' }, context: makeCtx(_TOKEN) });
		await new Promise((r) => setTimeout(r, 0));

		const protocols: string[] = WSSpy.mock.calls[0][1];
		expect(protocols).toEqual([`aptl-token.${_TOKEN}`]);
	});

	it('passes empty subprotocols array when wsToken is empty', async () => {
		render(Terminal, { props: { container: 'kali' }, context: makeCtx('') });
		await new Promise((r) => setTimeout(r, 0));

		const protocols: string[] = WSSpy.mock.calls[0][1];
		expect(protocols).toEqual([]);
	});

	it('encodes container name in the WS path', async () => {
		render(Terminal, { props: { container: 'metasploitable' }, context: makeCtx(_TOKEN) });
		await new Promise((r) => setTimeout(r, 0));

		const url: string = WSSpy.mock.calls[0][0];
		expect(url).toContain('/api/terminal/ws/metasploitable');
	});
});
