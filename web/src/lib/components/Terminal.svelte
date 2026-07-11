<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { Terminal } from '@xterm/xterm';
	import { FitAddon } from '@xterm/addon-fit';
	import { WebLinksAddon } from '@xterm/addon-web-links';
	import '@xterm/xterm/css/xterm.css';
	import {
		describeErrorFrame,
		describeTerminalClose,
		describeTicketFailure,
		fetchTerminalTicket,
		terminalWsUrl,
		TerminalTicketError,
		type TerminalStatus
	} from '$lib/bff';

	interface Props {
		container: string;
		/**
		 * Optional callback invoked whenever the connection status changes, so a
		 * host surface (e.g. the focused terminal header) can reflect the state.
		 */
		onstatechange?: (status: TerminalStatus) => void;
		/** xterm font size (px); sourced from operator preferences (UI-008f). */
		fontSize?: number;
		/** xterm scrollback (lines); sourced from operator preferences (UI-008f). */
		scrollback?: number;
	}

	let { container, onstatechange, fontSize = 14, scrollback = 1000 }: Props = $props();

	let terminalDiv: HTMLDivElement;
	let term: Terminal | null = null;
	let ws: WebSocket | null = null;
	let fitAddon: FitAddon | null = null;
	let resizeObserver: ResizeObserver | null = null;
	// Set in onDestroy so the async ticket→WebSocket flow can detect teardown
	// that happened while the ticket request was in flight and avoid opening an
	// orphan socket after the component is gone.
	let destroyed = false;
	// True once the session has carried real SSH output, so a subsequent close
	// is reported as "session ended" rather than "refused".
	let receivedData = false;

	// Narrow, accessible connection status surfaced OUTSIDE the xterm canvas so
	// assistive tech and sighted users both see rejection reasons (the xterm
	// viewport is a canvas that screen readers cannot follow).
	let status = $state<TerminalStatus>({
		phase: 'connecting',
		text: 'Connecting…',
		isError: false
	});

	function setStatus(next: TerminalStatus): void {
		status = next;
		onstatechange?.(next);
	}

	const dotClass = $derived(
		status.phase === 'connected'
			? 'bg-aptl-green'
			: status.phase === 'error'
				? 'bg-aptl-red'
				: status.phase === 'closed'
					? 'bg-aptl-text-muted'
					: 'bg-aptl-amber'
	);

	onMount(() => {
		term = new Terminal({
			cursorBlink: true,
			fontFamily: 'monospace',
			fontSize,
			scrollback,
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
			} catch (err) {
				if (!destroyed) {
					const httpStatus = err instanceof TerminalTicketError ? err.status : 0;
					const text = describeTicketFailure(httpStatus);
					setStatus({ phase: 'error', text, isError: true });
					term?.write(`\r\n\x1b[31m${text}\x1b[0m\r\n`);
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
				setStatus({ phase: 'connecting', text: `Connecting to ${container}…`, isError: false });
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
						if (!receivedData) {
							receivedData = true;
							setStatus({ phase: 'connected', text: `Connected to ${container}.`, isError: false });
						}
						term?.write(msg.data);
					} else if (msg.type === 'error') {
						setStatus(describeErrorFrame(msg.message));
						term?.write('\r\n\x1b[31mError: ' + msg.message + '\x1b[0m\r\n');
					}
				} catch {
					// Non-JSON data, write directly
					term?.write(event.data);
				}
			};

			ws.onclose = (event) => {
				// Preserve a specific error already surfaced (e.g. a {type:"error"}
				// frame) when the close carries no additional reason of its own.
				if (!(status.isError && !(event.reason ?? '').trim())) {
					setStatus(describeTerminalClose(event.code, event.reason ?? '', receivedData));
				}
				term?.write(`\r\n\x1b[33m${status.text}\x1b[0m\r\n`);
			};

			// Let onclose report the narrow reason; onerror only precedes it with no
			// detail, so avoid overwriting a good reason with a generic error here.
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

<div class="flex h-full w-full flex-col">
	<div
		class="flex items-center gap-2 border-b border-aptl-border bg-aptl-surface px-3 py-1.5 text-xs {status.isError
			? 'text-aptl-red'
			: 'text-aptl-text-muted'}"
		role="status"
		aria-live="polite"
		data-phase={status.phase}
	>
		<span class="h-1.5 w-1.5 shrink-0 rounded-full {dotClass}" aria-hidden="true"></span>
		<span>{status.text}</span>
	</div>
	<div bind:this={terminalDiv} class="min-h-0 w-full flex-1"></div>
</div>
