/**
 * Browser-Facing Facade helpers for the single-origin terminal flow (ADR-039).
 *
 * All calls use relative paths so the browser sends NO Authorization header
 * and NO API token.  The reverse proxy (Vite dev server, Nginx/Caddy in prod)
 * routes /api/* to the Python backend and, where needed, injects auth.
 */

import { sessionHeaders } from './session';

/**
 * Build the same-origin WebSocket URL for the given container terminal.
 *
 * Derives scheme and host exclusively from window.location so the URL always
 * matches the page origin — never a hardcoded host or port.
 */
export function terminalWsUrl(container: string): string {
	const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
	return `${scheme}//${window.location.host}/api/terminal/ws/${container}`;
}

/**
 * Obtain a short-lived opaque ticket for opening a terminal WebSocket.
 *
 * The same-origin fetch lets the server inject the backend auth credential;
 * the browser never sees or stores any API token.  Throws on non-ok status.
 */
export async function fetchTerminalTicket(): Promise<string> {
	// Same-origin fetch carries the HttpOnly cookie automatically and the
	// port-scoped session header explicitly (both auth factors), so the server
	// injects the backend credential; the browser never sees an API token.
	const res = await fetch('/api/terminal/ticket', { headers: sessionHeaders() });
	if (!res.ok) {
		throw new Error(`Terminal ticket request failed (${res.status})`);
	}
	const { ticket } = (await res.json()) as { ticket: string; expires_in: number };
	return ticket;
}
