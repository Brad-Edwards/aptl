/**
 * Port-scoped session second factor for the single-origin BFF (UI-008a / ADR-039).
 *
 * The server authenticates browser /api/* calls with TWO independent factors: an
 * HttpOnly `aptl_session` cookie (XSS-safe, but not port-scoped) and the header
 * token handled here (port-scoped, but XSS-readable). Requiring both closes the
 * cross-port cookie leak: cookies are scoped by host, not port, so the cookie is
 * also sent to any other `127.0.0.1:<port>`; a sibling local process on another
 * loopback port could steal it. This header token lives in `sessionStorage`,
 * which is scoped by origin INCLUDING port and is never auto-sent on navigation,
 * so a sibling port can neither read it nor have the browser send it.
 *
 * The token arrives once, in the login redirect URL fragment (`/#<param>=<tok>`)
 * — a fragment is never transmitted to any server (no logs, no Referer, no
 * cross-port leak) and is readable only by same-origin page JS. We move it into
 * sessionStorage and scrub the fragment.
 */

// Mirrors aptl.api.session.SESSION_HEADER_PARAM / SESSION_HEADER — keep in sync.
const FRAGMENT_PARAM = 'aptl_session';
const STORAGE_KEY = 'aptl_session';
export const SESSION_HEADER = 'X-APTL-Session';

/**
 * Capture the session header token from the login-redirect URL fragment into
 * sessionStorage, then scrub it from the URL. No-op when there is no token in
 * the fragment (e.g. an ordinary navigation). Safe to call on every load.
 */
export function captureSessionFromHash(): void {
	if (typeof globalThis.window === 'undefined') return;
	const hash = globalThis.location.hash;
	if (hash.length < 2) return;
	const params = new URLSearchParams(hash.slice(1));
	const token = params.get(FRAGMENT_PARAM);
	if (!token) return;

	try {
		sessionStorage.setItem(STORAGE_KEY, token);
	} catch {
		// sessionStorage unavailable (private mode edge cases); the API calls will
		// then 401 and the operator can re-open the launch URL.
		return;
	}

	// Scrub the token from the address bar / history, preserving any other
	// fragment params.
	params.delete(FRAGMENT_PARAM);
	const remaining = params.toString();
	const url =
		globalThis.location.pathname +
		globalThis.location.search +
		(remaining ? `#${remaining}` : '');
	history.replaceState(history.state, '', url);
}

/** Return the stored session header token, or null when none is present. */
export function getSessionToken(): string | null {
	if (typeof globalThis.window === 'undefined') return null;
	try {
		return sessionStorage.getItem(STORAGE_KEY);
	} catch {
		return null;
	}
}

/**
 * Return a Headers object carrying the session header token (when present),
 * merged onto any provided init headers. Use on every /api/* fetch.
 */
export function sessionHeaders(init?: HeadersInit): Headers {
	const headers = new Headers(init);
	const token = getSessionToken();
	if (token) headers.set(SESSION_HEADER, token);
	return headers;
}
