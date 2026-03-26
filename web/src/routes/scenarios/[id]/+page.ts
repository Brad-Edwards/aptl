import { error } from '@sveltejs/kit';
import type { ScenarioDefinition } from '$lib/types';

export async function load({
	params,
	fetch
}): Promise<{ scenario: ScenarioDefinition }> {
	const res = await fetch(`/api/scenarios/${encodeURIComponent(params.id)}`);
	if (!res.ok) {
		const text = await res.text();
		error(res.status, `Failed to load scenario: ${text}`);
	}
	const scenario: ScenarioDefinition = await res.json();
	return { scenario };
}
