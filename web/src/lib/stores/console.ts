import { writable } from 'svelte/store';
import type { ConsoleState } from '../console/types';
import { getState } from '../console/api';

const EMPTY: ConsoleState = {
	sessions: [],
	scratchpads: [],
	servers: [],
	provider: { provider: '', model: '', live: false, detail: '' }
};

export const consoleState = writable<ConsoleState>(EMPTY);
export const consoleLoading = writable(false);
export const consoleError = writable<string | null>(null);

/** Reload the full console state from the API. */
export async function refreshConsole(): Promise<ConsoleState> {
	consoleLoading.set(true);
	consoleError.set(null);
	try {
		const state = await getState();
		consoleState.set(state);
		return state;
	} catch (err) {
		consoleError.set(String(err));
		throw err;
	} finally {
		consoleLoading.set(false);
	}
}
