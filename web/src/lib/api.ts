import type { AppConfig, LabActionResponse, LabStatus, ScenarioSummary } from './types';

const BASE = '/api';

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
	const res = await fetch(`${BASE}${path}`, init);
	if (!res.ok) {
		const text = await res.text();
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

export async function getScenario(id: string): Promise<Record<string, unknown>> {
	return fetchJSON<Record<string, unknown>>(`/scenarios/${encodeURIComponent(id)}`);
}

export async function getConfig(): Promise<AppConfig> {
	return fetchJSON<AppConfig>('/config');
}

/** Create an SSE connection to the lab events stream. */
export function subscribeLabEvents(onMessage: (status: LabStatus) => void): EventSource {
	const es = new EventSource(`${BASE}/lab/events`);
	es.addEventListener('lab_status', (event) => {
		const data = JSON.parse((event as MessageEvent).data) as LabStatus;
		onMessage(data);
	});
	return es;
}
