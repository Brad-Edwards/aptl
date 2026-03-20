import { writable } from 'svelte/store';
import type { LabStatus } from '../types';
import { getLabStatus, subscribeLabEvents } from '../api';

export const labStatus = writable<LabStatus>({
	running: false,
	containers: [],
	error: ''
});

export const labLoading = writable(false);

let eventSource: EventSource | null = null;

/** Fetch initial lab status and start SSE subscription. */
export function initLabStore(): void {
	labLoading.set(true);
	getLabStatus()
		.then((status) => {
			labStatus.set(status);
		})
		.catch((err) => {
			labStatus.update((s) => ({ ...s, error: String(err) }));
		})
		.finally(() => {
			labLoading.set(false);
		});

	// Start SSE
	if (eventSource) {
		eventSource.close();
	}
	eventSource = subscribeLabEvents((status) => {
		labStatus.set(status);
	});
}

/** Stop SSE subscription. */
export function destroyLabStore(): void {
	if (eventSource) {
		eventSource.close();
		eventSource = null;
	}
}
