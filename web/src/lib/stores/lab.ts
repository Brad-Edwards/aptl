import { writable } from 'svelte/store';
import type { LabStatus } from '../types';
import { getLabStatus, subscribeLabEvents, type EventSubscription } from '../api';

export const labStatus = writable<LabStatus>({
	running: false,
	containers: [],
	error: null
});

export const labLoading = writable(false);

let subscription: EventSubscription | null = null;
let generation = 0;

const RECONNECT_DELAY_MS = 5000;

/** Fetch initial lab status and start SSE subscription. */
export function initLabStore(): void {
	const currentGeneration = ++generation;

	labLoading.set(true);
	getLabStatus()
		.then((status) => {
			if (currentGeneration === generation) {
				labStatus.set(status);
			}
		})
		.catch((err) => {
			if (currentGeneration === generation) {
				labStatus.update((s) => ({ ...s, error: String(err) }));
			}
		})
		.finally(() => {
			if (currentGeneration === generation) {
				labLoading.set(false);
			}
		});

	// Start SSE
	if (subscription) {
		subscription.close();
	}
	subscription = subscribeLabEvents(
		(status) => {
			if (currentGeneration === generation) {
				labStatus.set(status);
			}
		},
		() => {
			// Stream ended or failed (not an explicit close): schedule reconnect,
			// which re-fetches a fresh status and re-subscribes.
			if (currentGeneration === generation) {
				setTimeout(() => {
					if (currentGeneration === generation) {
						initLabStore();
					}
				}, RECONNECT_DELAY_MS);
			}
		}
	);
}

/** Stop SSE subscription. */
export function destroyLabStore(): void {
	generation++;
	if (subscription) {
		subscription.close();
		subscription = null;
	}
}
