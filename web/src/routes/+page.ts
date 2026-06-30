import { getScenarios } from '$lib/api';
import type { ScenarioSummary } from '$lib/types';

/**
 * Load the scenario catalog summary for the Lab Home entry points.
 *
 * Routes through `getScenarios()` (not a raw `fetch`) so the call carries the
 * port-scoped `X-APTL-Session` header via the shared API boundary, and threads
 * the load-provided `event.fetch` into it so the request resolves correctly in
 * every load context (the SvelteKit-idiomatic load fetch) rather than reaching
 * for a browser-only global. A failure (API unreachable, not-yet-authenticated,
 * transport error) degrades to an empty list with an error flag so the page can
 * show a stable catalog-error state rather than crashing the route.
 */
export async function load({ fetch }): Promise<{
	scenarios: ScenarioSummary[];
	scenariosError: boolean;
}> {
	try {
		return { scenarios: await getScenarios(fetch), scenariosError: false };
	} catch {
		return { scenarios: [], scenariosError: true };
	}
}
