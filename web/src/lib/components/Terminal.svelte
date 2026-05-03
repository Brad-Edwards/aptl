<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { Terminal } from '@xterm/xterm';
	import { FitAddon } from '@xterm/addon-fit';
	import { WebLinksAddon } from '@xterm/addon-web-links';
	import '@xterm/xterm/css/xterm.css';

	interface Props {
		container: string;
	}

	let { container }: Props = $props();

	let terminalDiv: HTMLDivElement;
	let term: Terminal | null = null;
	let ws: WebSocket | null = null;
	let fitAddon: FitAddon | null = null;
	let resizeObserver: ResizeObserver | null = null;

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

		// WebSocket connection
		const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
		const wsUrl = `${protocol}//${window.location.host}/api/terminal/ws/${container}`;
		ws = new WebSocket(wsUrl);

		ws.onopen = () => {
			term?.write('\r\nConnecting to ' + container + '...\r\n');
			// Send initial size
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
	});

	onDestroy(() => {
		resizeObserver?.disconnect();
		ws?.close();
		term?.dispose();
	});
</script>

<div bind:this={terminalDiv} class="h-full w-full"></div>
