import type { ScenarioSummary } from '$lib/types';

export async function load({ fetch }): Promise<{ scenarios: ScenarioSummary[] }> {
	try {
		const res = await fetch('/api/scenarios');
		if (res.ok) {
			const scenarios: ScenarioSummary[] = await res.json();
			return { scenarios };
		}
	} catch {
		// API may not be available during SSR build
	}
	return { scenarios: [] };
}
