/**
 * Browser-Facing Facade helpers for the single-origin terminal flow (ADR-039).
 *
 * All calls use relative paths so the browser sends NO Authorization header
 * and NO API token.  The reverse proxy (Vite dev server, Nginx/Caddy in prod)
 * routes /api/* to the Python backend and, where needed, injects auth.
 */

import { sessionHeaders } from './session';

/** Lifecycle phase of a terminal connection, surfaced to assistive tech. */
export type TerminalStatusPhase = 'connecting' | 'connected' | 'closed' | 'error';

/**
 * A narrow, translation-ready description of the terminal connection state.
 *
 * `text` never carries a secret or a raw server exception — only the fixed,
 * operator-facing rejection categories the backend already emits (ADR-039 /
 * ADR-040) or a generic fallback. `isError` drives the accessible status
 * region's styling and severity.
 */
export interface TerminalStatus {
	phase: TerminalStatusPhase;
	text: string;
	isError: boolean;
}

/**
 * Error thrown by {@link fetchTerminalTicket} on a non-ok response, carrying
 * the HTTP status so the caller can distinguish an auth/session failure (401 /
 * 403) from a generic start failure without echoing any server body.
 */
export class TerminalTicketError extends Error {
	readonly status: number;
	constructor(status: number) {
		super(`Terminal ticket request failed (${status})`);
		this.name = 'TerminalTicketError';
		this.status = status;
	}
}

// Fixed map from the backend's narrow WebSocket close reasons
// (src/aptl/api/routers/terminal.py) to translation-ready operator copy. An
// unmapped-but-present reason is surfaced verbatim (the server guarantees it is
// a narrow, secret-free category); an absent reason falls back on the code.
const CLOSE_REASON_TEXT: Record<string, string> = {
	Unauthorized: 'Not authorized to open a terminal session.',
	'Origin not allowed': 'The browser origin was rejected (same-origin policy).',
	'Unknown container': 'That container is not an allowed terminal target.',
	'Lab not running': 'The lab is not running.',
	'Container not available': 'The container is not currently available.',
	'Host keys not pinned': 'SSH host keys are not pinned — restart the lab.'
};

/**
 * Build the same-origin WebSocket URL for the given container terminal.
 *
 * Derives scheme and host exclusively from globalThis.location so the URL always
 * matches the page origin — never a hardcoded host or port.
 */
export function terminalWsUrl(container: string): string {
	const scheme = globalThis.location.protocol === 'https:' ? 'wss:' : 'ws:';
	return `${scheme}//${globalThis.location.host}/api/terminal/ws/${container}`;
}

/**
 * Narrow, translation-ready description of a failed terminal-ticket request.
 *
 * 401 / 403 mean the operator session is missing or expired; any other status
 * is a generic start failure. No server response body is echoed — only the
 * status drives the category, so no server detail leaks into the UI.
 */
export function describeTicketFailure(status: number): string {
	if (status === 401 || status === 403) {
		return 'Not authorized to open a terminal — your session may have expired.';
	}
	return 'Could not start the terminal session.';
}

/**
 * Narrow description of a server terminal error frame (`{type:"error"}`).
 *
 * The backend already sends a fixed, secret-free category message (e.g. "Lab
 * is not running", "SSH connection failed"), so it is surfaced verbatim.
 */
export function describeErrorFrame(message: string): TerminalStatus {
	return { phase: 'error', text: message, isError: true };
}

/**
 * Narrow description of a terminal WebSocket close.
 *
 * Prefers the server's explicit close reason (a fixed narrow category). When
 * the reason is absent — pre-accept rejections (auth / origin) reach the
 * browser as an abnormal 1006 close with no reason — it falls back on the code
 * and whether the session ever carried data. Never echoes secrets.
 */
export function describeTerminalClose(
	code: number,
	reason: string,
	receivedData: boolean
): TerminalStatus {
	const trimmed = reason.trim();
	if (trimmed) {
		return { phase: 'error', text: CLOSE_REASON_TEXT[trimmed] ?? trimmed, isError: true };
	}
	// A socket that never carried data and closed abnormally (anything but the
	// normal 1000) was almost certainly refused at a pre-accept gate.
	if (!receivedData && code !== 1000) {
		return {
			phase: 'error',
			text: 'Terminal connection refused (unauthorized or blocked).',
			isError: true
		};
	}
	if (receivedData) {
		return { phase: 'closed', text: 'Terminal session ended.', isError: false };
	}
	return { phase: 'closed', text: 'Terminal connection closed.', isError: false };
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
		throw new TerminalTicketError(res.status);
	}
	const { ticket } = (await res.json()) as { ticket: string; expires_in: number };
	return ticket;
}
