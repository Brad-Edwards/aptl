import type {
	AppConfig,
	KillActionResponse,
	LabActionResponse,
	LabStatus,
	ScenarioDetail,
	ScenarioSummary
} from './types';
import { sessionHeaders } from './session';

const BASE = '/api';
const MAX_ERROR_TEXT_LENGTH = 500;

/** An error from a non-2xx `/api/*` response, carrying the HTTP status so
 *  callers (e.g. the scenario workbench loader) can branch on it — a 404 maps
 *  to a route-level not-found, anything else to a generic unavailable state. */
export class ApiError extends Error {
	readonly status: number;

	constructor(status: number, message: string) {
		super(message);
		this.name = 'ApiError';
		this.status = status;
	}
}

async function fetchJSON<T>(
	path: string,
	init?: RequestInit,
	fetchFn: typeof fetch = fetch
): Promise<T> {
	// Every /api/* call carries the port-scoped session header (the second auth
	// factor); the HttpOnly cookie rides along automatically. See ./session.
	// `fetchFn` defaults to the global `fetch` for browser-side calls; a
	// SvelteKit `load` passes its own `event.fetch` so relative URLs resolve
	// correctly in every load context (SSR/prerender included).
	const res = await fetchFn(`${BASE}${path}`, {
		...init,
		headers: sessionHeaders(init?.headers)
	});
	if (!res.ok) {
		let text = await res.text();
		if (text.length > MAX_ERROR_TEXT_LENGTH) {
			text = text.slice(0, MAX_ERROR_TEXT_LENGTH) + '...';
		}
		throw new ApiError(res.status, `API error ${res.status}: ${text}`);
	}
	return res.json() as Promise<T>;
}

export async function getLabStatus(): Promise<LabStatus> {
	return fetchJSON<LabStatus>('/lab/status');
}

export async function startLab(): Promise<LabActionResponse> {
	return fetchJSON<LabActionResponse>('/lab/start', { method: 'POST' });
}

export async function stopLab(): Promise<LabActionResponse> {
	return fetchJSON<LabActionResponse>('/lab/stop', { method: 'POST' });
}

/**
 * Emergency kill switch. Always terminates MCP processes and clears session
 * state; `containers` widens the blast radius to also force-stop every lab
 * container. Returns the distinct `KillActionResponse` shape (not the
 * start/stop `LabActionResponse`).
 */
export async function killLab(containers: boolean): Promise<KillActionResponse> {
	return fetchJSON<KillActionResponse>(`/lab/kill?containers=${containers}`, {
		method: 'POST'
	});
}

export async function getScenarios(
	fetchFn: typeof fetch = fetch
): Promise<ScenarioSummary[]> {
	return fetchJSON<ScenarioSummary[]>('/scenarios', undefined, fetchFn);
}

export async function getScenario(
	id: string,
	fetchFn: typeof fetch = fetch
): Promise<ScenarioDetail> {
	return fetchJSON<ScenarioDetail>(
		`/scenarios/${encodeURIComponent(id)}`,
		undefined,
		fetchFn
	);
}

export async function getConfig(fetchFn: typeof fetch = fetch): Promise<AppConfig> {
	return fetchJSON<AppConfig>('/config', undefined, fetchFn);
}

/** A cancellable subscription to the lab events stream. */
export interface EventSubscription {
	/** Stop the subscription and abort the underlying request. */
	close(): void;
}

/** Parse one raw SSE event block and dispatch `lab_status` events. */
function dispatchSseEvent(
	raw: string,
	onMessage: (status: LabStatus) => void
): void {
	let event = 'message';
	const dataLines: string[] = [];
	for (const line of raw.split('\n')) {
		if (line.startsWith('event:')) {
			event = line.slice('event:'.length).trim();
		} else if (line.startsWith('data:')) {
			dataLines.push(line.slice('data:'.length).trim());
		}
	}
	if (event !== 'lab_status' || dataLines.length === 0) return;
	try {
		onMessage(JSON.parse(dataLines.join('\n')) as LabStatus);
	} catch {
		// Ignore a malformed event rather than tearing down the stream.
	}
}

/**
 * Subscribe to the lab events SSE stream.
 *
 * Uses `fetch` streaming rather than `EventSource` because `EventSource` cannot
 * send the `X-APTL-Session` header (the port-scoped auth factor); `fetch` can.
 * The terminal WebSocket — which also cannot send headers — uses a ticket
 * instead. `onError` fires when the stream ends or fails for any reason other
 * than an explicit `close()`, mirroring the previous reconnect trigger.
 */
export function subscribeLabEvents(
	onMessage: (status: LabStatus) => void,
	onError?: () => void
): EventSubscription {
	const controller = new AbortController();
	let closed = false;

	const fail = () => {
		if (!closed) onError?.();
	};

	(async () => {
		try {
			const res = await fetch(`${BASE}/lab/events`, {
				headers: sessionHeaders({ Accept: 'text/event-stream' }),
				signal: controller.signal
			});
			if (!res.ok || !res.body) {
				fail();
				return;
			}
			const reader = res.body.getReader();
			const decoder = new TextDecoder();
			let buffer = '';
			for (;;) {
				const { value, done } = await reader.read();
				if (done) break;
				// Strip CR so events split cleanly on a blank line regardless of
				// CRLF vs LF line endings.
				buffer += decoder.decode(value, { stream: true }).replaceAll('\r', '');
				let idx: number;
				while ((idx = buffer.indexOf('\n\n')) !== -1) {
					dispatchSseEvent(buffer.slice(0, idx), onMessage);
					buffer = buffer.slice(idx + 2);
				}
			}
			fail();
		} catch {
			// Network error or abort; only surface non-explicit teardown.
			fail();
		}
	})();

	return {
		close() {
			closed = true;
			controller.abort();
		}
	};
}
