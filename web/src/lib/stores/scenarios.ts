import { writable } from 'svelte/store';
import type { ScenarioSummary } from '../types';
import { getScenarios } from '../api';

export const scenarios = writable<ScenarioSummary[]>([]);
export const scenariosLoading = writable(false);
export const scenariosError = writable('');

export async function loadScenarios(): Promise<void> {
	scenariosLoading.set(true);
	scenariosError.set('');
	try {
		const data = await getScenarios();
		scenarios.set(data);
	} catch (err) {
		scenariosError.set(String(err));
	} finally {
		scenariosLoading.set(false);
	}
}
