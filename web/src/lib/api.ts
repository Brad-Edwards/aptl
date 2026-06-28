import type {
	AppConfig,
	LabActionResponse,
	LabStatus,
	ScenarioDefinition,
	ScenarioSummary
} from './types';
import { sessionHeaders } from './session';

const BASE = '/api';
const MAX_ERROR_TEXT_LENGTH = 500;

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
	// Every /api/* call carries the port-scoped session header (the second auth
	// factor); the HttpOnly cookie rides along automatically. See ./session.
	const res = await fetch(`${BASE}${path}`, {
		...init,
		headers: sessionHeaders(init?.headers)
	});
	if (!res.ok) {
		let text = await res.text();
		if (text.length > MAX_ERROR_TEXT_LENGTH) {
			text = text.slice(0, MAX_ERROR_TEXT_LENGTH) + '...';
		}
		throw new Error(`API error ${res.status}: ${text}`);
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

export async function getScenarios(): Promise<ScenarioSummary[]> {
	return fetchJSON<ScenarioSummary[]>('/scenarios');
}

export async function getScenario(id: string): Promise<ScenarioDefinition> {
	return fetchJSON<ScenarioDefinition>(`/scenarios/${encodeURIComponent(id)}`);
}

export async function getConfig(): Promise<AppConfig> {
	return fetchJSON<AppConfig>('/config');
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
