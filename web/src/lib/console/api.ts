import type {
	ConsoleState,
	Role,
	Scratchpad,
	Session,
	StreamEvent
} from './types';

const BASE = '/api/console';
const MAX_ERROR_TEXT_LENGTH = 500;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
	const res = await fetch(`${BASE}${path}`, {
		...init,
		headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) }
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

export async function getState(): Promise<ConsoleState> {
	return request<ConsoleState>('/state');
}

export async function createSession(body: {
	role: Role;
	title?: string;
	mcp_servers?: string[];
	scratchpads?: string[];
}): Promise<Session> {
	return request<Session>('/sessions', { method: 'POST', body: JSON.stringify(body) });
}

export async function updateSession(
	id: string,
	body: Partial<Pick<Session, 'title' | 'role' | 'mcp_servers' | 'scratchpads'>>
): Promise<Session> {
	return request<Session>(`/sessions/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
}

export async function deleteSession(id: string): Promise<void> {
	await request(`/sessions/${id}`, { method: 'DELETE' });
}

export async function getSession(id: string): Promise<Session> {
	return request<Session>(`/sessions/${id}`);
}

export async function createScratchpad(body: { name: string; content?: string }): Promise<Scratchpad> {
	return request<Scratchpad>('/scratchpads', { method: 'POST', body: JSON.stringify(body) });
}

export async function updateScratchpad(
	id: string,
	body: { name?: string; content?: string }
): Promise<Scratchpad> {
	return request<Scratchpad>(`/scratchpads/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
}

export async function deleteScratchpad(id: string): Promise<void> {
	await request(`/scratchpads/${id}`, { method: 'DELETE' });
}

/**
 * Send a message and stream the agent turn.
 *
 * SSE over POST is not supported by `EventSource`, so we read the response
 * body ourselves and split on the SSE record separator (blank line). Each
 * record's `data:` payload is a JSON {@link StreamEvent}.
 */
export async function streamMessage(
	sessionId: string,
	content: string,
	onEvent: (event: StreamEvent) => void,
	signal?: AbortSignal
): Promise<void> {
	const res = await fetch(`${BASE}/sessions/${sessionId}/messages`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ content }),
		signal
	});
	if (!res.ok || !res.body) {
		const text = await res.text().catch(() => '');
		throw new Error(`Stream error ${res.status}: ${text.slice(0, MAX_ERROR_TEXT_LENGTH)}`);
	}

	const reader = res.body.getReader();
	const decoder = new TextDecoder();
	let buffer = '';

	for (;;) {
		const { value, done } = await reader.read();
		if (done) break;
		buffer += decoder.decode(value, { stream: true });
		buffer = drainRecords(buffer, onEvent);
	}
	// Flush any trailing record.
	drainRecords(buffer + '\n\n', onEvent);
}

/** Parse complete SSE records out of the buffer; return the unconsumed tail. */
export function drainRecords(buffer: string, onEvent: (event: StreamEvent) => void): string {
	let working = buffer;
	let sep = working.indexOf('\n\n');
	while (sep !== -1) {
		const record = working.slice(0, sep);
		working = working.slice(sep + 2);
		const event = parseRecord(record);
		if (event) onEvent(event);
		sep = working.indexOf('\n\n');
	}
	return working;
}

function parseRecord(record: string): StreamEvent | null {
	const dataLines = record
		.split('\n')
		.filter((line) => line.startsWith('data:'))
		.map((line) => line.slice(5).trimStart());
	if (dataLines.length === 0) return null;
	try {
		return JSON.parse(dataLines.join('\n')) as StreamEvent;
	} catch {
		return null;
	}
}
