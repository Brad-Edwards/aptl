<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { Terminal } from '@xterm/xterm';
	import { FitAddon } from '@xterm/addon-fit';
	import { WebLinksAddon } from '@xterm/addon-web-links';
	import '@xterm/xterm/css/xterm.css';
	import { fetchTerminalTicket, terminalWsUrl } from '$lib/bff';

	interface Props {
		container: string;
	}

	let { container }: Props = $props();

	let terminalDiv: HTMLDivElement;
	let term: Terminal | null = null;
	let ws: WebSocket | null = null;
	let fitAddon: FitAddon | null = null;
	let resizeObserver: ResizeObserver | null = null;
	// Set in onDestroy so the async ticket→WebSocket flow can detect teardown
	// that happened while the ticket request was in flight and avoid opening an
	// orphan socket after the component is gone.
	let destroyed = false;

	onMount(() => {
		term = new Terminal({
			cursorBlink: true,
			fontFamily: 'monospace',
			fontSize: 14,
			theme: {
				background: '#1a1d23',
				foreground: '#e2e8f0',
				cursor: '#6366f1',
				selectionBackground: '#6366f140',
				black: '#1a1d23',
				red: '#ef4444',
				green: '#22c55e',
				yellow: '#eab308',
				blue: '#6366f1',
				magenta: '#a855f7',
				cyan: '#06b6d4',
				white: '#e2e8f0'
			}
		});

		fitAddon = new FitAddon();
		term.loadAddon(fitAddon);
		term.loadAddon(new WebLinksAddon());
		term.open(terminalDiv);
		fitAddon.fit();

		// Forward terminal input to WebSocket
		term.onData((data) => {
			if (ws?.readyState === WebSocket.OPEN) {
				ws.send(JSON.stringify({ type: 'stdin', data }));
			}
		});

		// Forward terminal resize to WebSocket
		term.onResize(({ cols, rows }) => {
			if (ws?.readyState === WebSocket.OPEN) {
				ws.send(JSON.stringify({ type: 'resize', cols, rows }));
			}
		});

		// Observe container resizes and refit terminal
		resizeObserver = new ResizeObserver(() => {
			fitAddon?.fit();
		});
		resizeObserver.observe(terminalDiv);

		// Async: fetch a short-lived ticket from the same-origin endpoint, then
		// open the WebSocket.  No token is stored in the browser — the server
		// injects backend auth for the ticket endpoint; the ticket itself is
		// opaque, single-use, and short-lived (≤30 s per ADR-039).
		(async () => {
			let ticket: string;
			try {
				ticket = await fetchTerminalTicket();
			} catch {
				if (!destroyed) {
					term?.write('\r\n\x1b[31mCould not start terminal session.\x1b[0m\r\n');
				}
				return;
			}

			// The component may have been torn down while the ticket request was
			// in flight; don't open a socket that onDestroy can no longer see.
			if (destroyed) {
				return;
			}

			const wsUrl = terminalWsUrl(container);
			ws = new WebSocket(wsUrl, [`aptl-token.${ticket}`]);

			// Defensive: if teardown raced past the check above, close immediately.
			if (destroyed) {
				ws.close();
				ws = null;
				return;
			}

			ws.onopen = () => {
				term?.write('\r\nConnecting to ' + container + '...\r\n');
				// Send initial terminal size so the PTY is correctly sized from the start.
				if (term) {
					ws?.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
				}
			};

			ws.onmessage = (event) => {
				try {
					const msg = JSON.parse(event.data);
					if (msg.type === 'stdout') {
						term?.write(msg.data);
					} else if (msg.type === 'error') {
						term?.write('\r\n\x1b[31mError: ' + msg.message + '\x1b[0m\r\n');
					}
				} catch {
					// Non-JSON data, write directly
					term?.write(event.data);
				}
			};

			ws.onclose = () => {
				term?.write('\r\n\x1b[33mConnection closed.\x1b[0m\r\n');
			};

			ws.onerror = () => {
				term?.write('\r\n\x1b[31mWebSocket error.\x1b[0m\r\n');
			};
		})();
	});

	onDestroy(() => {
		destroyed = true;
		resizeObserver?.disconnect();
		ws?.close();
		term?.dispose();
	});
</script>

<div bind:this={terminalDiv} class="h-full w-full"></div>
